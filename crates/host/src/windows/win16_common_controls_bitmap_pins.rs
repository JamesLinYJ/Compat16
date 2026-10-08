//! Owner-thread pinning for the source bitmap consumed by CreateToolbarEx.

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostWindow};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DestroyWindow, GetClassNameW, GetDlgCtrlID, GetParent, IsWindow, WM_NCDESTROY,
};

use super::win16_gdi_bitmap_lease::Win16BitmapLease;
use super::win16_window_worker::{self, WorkerState};

#[path = "win16_common_controls_bitmap_stage.rs"]
mod stage_slots;
pub(super) use stage_slots::{
    ToolbarBitmapStageSlot, reserve_stage_slot, retain_unbound_owner, stage,
};
#[path = "win16_common_controls_bitmap_lease_retention.rs"]
mod lease_retention;
pub(super) use lease_retention::{release_unconsumed_leases, reserve_unconsumed_leases};
#[path = "win16_common_controls_bitmap_retention.rs"]
mod retention;
pub(super) use retention::ToolbarBitmapRetention;

static NEXT_WORKER_RETIREMENT_ID: AtomicU64 = AtomicU64::new(1);
static RETAINED_WORKER_BITMAPS: OnceLock<Mutex<RetainedWorkerBitmaps>> = OnceLock::new();

struct RetainedWorkerBitmaps {
    pools: Vec<RetainedWorkerBitmapPool>,
    reserved: usize,
}

struct RetainedWorkerBitmapPool {
    worker_id: u64,
    storage: Arc<Mutex<ToolbarBitmapRetention>>,
    joined: bool,
    cleanup_cause: Option<Arc<RuntimeError>>,
}

fn retained_worker_bitmaps() -> &'static Mutex<RetainedWorkerBitmaps> {
    RETAINED_WORKER_BITMAPS.get_or_init(|| {
        Mutex::new(RetainedWorkerBitmaps {
            pools: Vec::new(),
            reserved: 0,
        })
    })
}

pub(super) fn allocate_worker_retirement_id() -> Result<u64, RuntimeError> {
    NEXT_WORKER_RETIREMENT_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 USER worker retirement identity exhausted",
            )
        })
}

pub(super) fn reserve_worker_retention_slot() -> Result<(), RuntimeError> {
    let mut retained = retained_worker_bitmaps()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let required = retained
        .pools
        .len()
        .checked_add(retained.reserved)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "toolbar bitmap retention capacity overflow",
            )
        })?;
    if required > retained.pools.capacity() {
        let additional = required - retained.pools.len();
        retained.pools.try_reserve(additional).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve process-owned toolbar bitmap retention",
                error,
            )
        })?;
    }
    retained.reserved += 1;
    Ok(())
}

pub(super) fn release_worker_retention_slot() -> Result<(), RuntimeError> {
    let mut retained = retained_worker_bitmaps()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    retained.reserved = retained.reserved.checked_sub(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar bitmap retention reservation underflow",
        )
    })?;
    Ok(())
}

/// Retry owners already retained after their specific worker was joined.
pub(super) fn retry_retained_after_join() -> Result<(), RuntimeError> {
    let mut retained = retained_worker_bitmaps()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut failure = None;
    let mut index = 0;
    while index < retained.pools.len() {
        if !retained.pools[index].joined {
            index += 1;
            continue;
        }
        let storage = Arc::clone(&retained.pools[index].storage);
        match retire_joined_pool(&storage) {
            Ok(()) if pool_is_empty(&storage) => {
                retained.pools.remove(index);
            }
            Ok(()) => index += 1,
            Err(error) => {
                let previous = retained.pools[index].cleanup_cause.take();
                let (cause, reported) = keep_cleanup_cause(previous, error);
                retained.pools[index].cleanup_cause = Some(cause);
                remember(&mut failure, reported);
                index += 1;
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

/// Retire a worker's remaining toolbar pins only after its JoinHandle returns.
pub(super) fn retire_worker_after_join(
    worker_id: u64,
    storage: &Arc<Mutex<ToolbarBitmapRetention>>,
    retention_slot_reserved: &mut bool,
) -> Result<(), RuntimeError> {
    if !pool_matches_worker(storage, worker_id) {
        let error = RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar bitmap retention pool contains a different USER worker identity",
        );
        let (cause, reported) = keep_cleanup_cause(None, error);
        return match retain_joined_worker_pool(
            worker_id,
            storage,
            retention_slot_reserved,
            Some(cause),
        ) {
            Ok(()) => Err(reported),
            Err(cleanup) => Err(RuntimeError::with_source(
                reported.kind().with_cleanup(cleanup.kind()),
                "toolbar identity failure and process retention both failed",
                ToolbarBitmapCleanupFailure {
                    primary: reported,
                    cleanup,
                },
            )),
        };
    }
    let mut retained_cause = None;
    let mut failure = retire_joined_pool(storage).err().map(|error| {
        let (cause, reported) = keep_cleanup_cause(None, error);
        retained_cause = Some(cause);
        reported
    });
    let empty = pool_is_empty(storage);
    if empty && *retention_slot_reserved {
        *retention_slot_reserved = false;
        if let Err(error) = release_worker_retention_slot() {
            remember(&mut failure, error);
        }
    } else if !empty {
        if let Err(error) =
            retain_joined_worker_pool(worker_id, storage, retention_slot_reserved, retained_cause)
        {
            remember(&mut failure, error);
        }
    }
    failure.map_or(Ok(()), Err)
}

fn retain_joined_worker_pool(
    worker_id: u64,
    storage: &Arc<Mutex<ToolbarBitmapRetention>>,
    retention_slot_reserved: &mut bool,
    cleanup_cause: Option<Arc<RuntimeError>>,
) -> Result<(), RuntimeError> {
    let mut retained = retained_worker_bitmaps()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(index) = retained
        .pools
        .iter()
        .position(|pool| pool.worker_id == worker_id && Arc::ptr_eq(&pool.storage, storage))
    {
        if let Some(cause) = cleanup_cause {
            let incoming = RuntimeError::with_source(
                cause.kind(),
                "toolbar bitmap owner retained after cleanup failure",
                SharedBitmapFailure(cause),
            );
            let (merged, _) =
                keep_cleanup_cause(retained.pools[index].cleanup_cause.take(), incoming);
            retained.pools[index].cleanup_cause = Some(merged);
        }
        if *retention_slot_reserved {
            match retained.reserved.checked_sub(1) {
                Some(reserved) => {
                    retained.reserved = reserved;
                    *retention_slot_reserved = false;
                }
                None => {
                    let (cause, reported) = keep_cleanup_cause(
                        retained.pools[index].cleanup_cause.take(),
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "toolbar bitmap retention reservation underflow",
                        ),
                    );
                    retained.pools[index].cleanup_cause = Some(cause);
                    return Err(reported);
                }
            }
        }
        return Ok(());
    }
    if retained.pools.len() == retained.pools.capacity() {
        if let Err(error) = retained.pools.try_reserve(1) {
            let allocation = RuntimeError::with_source(
                Kind::ResourceExhausted,
                "grow process-owned toolbar bitmap retention",
                error,
            );
            return Err(match cleanup_cause {
                Some(cause) => {
                    let primary = RuntimeError::with_source(
                        cause.kind(),
                        "toolbar bitmap cleanup failed before retention",
                        SharedBitmapFailure(cause),
                    );
                    let kind = primary.kind().with_cleanup(allocation.kind());
                    RuntimeError::with_source(
                        kind,
                        "toolbar bitmap cleanup and owner retention both failed",
                        ToolbarBitmapCleanupFailure {
                            primary,
                            cleanup: allocation,
                        },
                    )
                }
                None => allocation,
            });
        }
    }
    let mut cause = cleanup_cause;
    let mut failure = None;
    if *retention_slot_reserved {
        match retained.reserved.checked_sub(1) {
            Some(reserved) => {
                retained.reserved = reserved;
                *retention_slot_reserved = false;
            }
            None => {
                *retention_slot_reserved = false;
                remember(
                    &mut failure,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "toolbar bitmap retention reservation underflow",
                    ),
                );
            }
        }
    } else {
        remember(
            &mut failure,
            RuntimeError::new(
                Kind::InternalInvariant,
                "live toolbar bitmap owners had no process-retention reservation",
            ),
        );
    }
    if let Some(error) = failure.take() {
        let (merged, reported) = keep_cleanup_cause(cause, error);
        cause = Some(merged);
        failure = Some(reported);
    }
    retained.pools.push(RetainedWorkerBitmapPool {
        worker_id,
        storage: Arc::clone(storage),
        joined: true,
        cleanup_cause: cause,
    });
    failure.map_or(Ok(()), Err)
}

fn retire_joined_pool(storage: &Arc<Mutex<ToolbarBitmapRetention>>) -> Result<(), RuntimeError> {
    let mut retained = storage
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut failure = None;
    retire_sidecar_vector(&mut retained.sidecars, &mut failure);
    let emergency_empty = if let Some(sidecars) = retained.emergency_sidecars.as_mut() {
        retire_sidecar_vector(sidecars, &mut failure);
        sidecars.is_empty()
    } else {
        false
    };
    if emergency_empty {
        retained.emergency_sidecars = None;
    }
    let overflow_empty = if let Some(sidecars) = retained.overflow_sidecars.as_mut() {
        retire_sidecar_vector(sidecars, &mut failure);
        sidecars.is_empty()
    } else {
        false
    };
    if overflow_empty {
        retained.overflow_sidecars = None;
    }
    if retained.reserved_slots != 0 {
        remember(
            &mut failure,
            RuntimeError::new(
                Kind::InternalInvariant,
                "joined toolbar bitmap pool still has unfulfilled owner reservations",
            ),
        );
    }
    if !retained.dc_release_owners.is_empty()
        || retained
            .emergency_dc_release_owners
            .as_ref()
            .is_some_and(|owners| !owners.is_empty())
        || retained
            .overflow_dc_release_owners
            .as_ref()
            .is_some_and(|owners| !owners.is_empty())
    {
        remember(
            &mut failure,
            RuntimeError::new(
                Kind::HostFailure,
                "toolbar HDC release owner remains retained after its creator thread exited",
            ),
        );
    }
    if retained.reserved_dc_release_slots != 0 {
        remember(
            &mut failure,
            RuntimeError::new(
                Kind::InternalInvariant,
                "joined toolbar pool still has outstanding HDC owner reservations",
            ),
        );
    }
    if let Some(cause) = retained.deferred_failure.take() {
        remember(
            &mut failure,
            RuntimeError::with_source(
                cause.kind(),
                "toolbar teardown retained an earlier ownership failure",
                SharedBitmapFailure(cause),
            ),
        );
    }
    if retained.deferred_owner_failure {
        remember(
            &mut failure,
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar owner remains inside a retained teardown diagnostic",
            ),
        );
    }
    failure.map_or(Ok(()), Err)
}

fn pool_is_empty(storage: &Arc<Mutex<ToolbarBitmapRetention>>) -> bool {
    let retained = storage
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    retained.sidecars.is_empty()
        && retained
            .emergency_sidecars
            .as_ref()
            .map_or(true, Vec::is_empty)
        && retained
            .overflow_sidecars
            .as_ref()
            .map_or(true, Vec::is_empty)
        && retained.reserved_slots == 0
        && retained.dc_release_owners.is_empty()
        && retained
            .emergency_dc_release_owners
            .as_ref()
            .map_or(true, Vec::is_empty)
        && retained
            .overflow_dc_release_owners
            .as_ref()
            .map_or(true, Vec::is_empty)
        && retained.reserved_dc_release_slots == 0
        && !retained.deferred_owner_failure
}

fn pool_matches_worker(storage: &Arc<Mutex<ToolbarBitmapRetention>>, worker_id: u64) -> bool {
    let retained = storage
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    retained
        .sidecars
        .iter()
        .chain(retained.emergency_sidecars.iter().flatten())
        .chain(retained.overflow_sidecars.iter().flatten())
        .all(|entry| entry.worker_retirement_id == worker_id)
        && retained
            .dc_release_owners
            .iter()
            .chain(retained.emergency_dc_release_owners.iter().flatten())
            .chain(retained.overflow_dc_release_owners.iter().flatten())
            .all(|owner| owner.worker_retirement_id == worker_id)
}

fn retire_sidecar_vector(
    sidecars: &mut Vec<ToolbarBitmapSidecar>,
    failure: &mut Option<RuntimeError>,
) {
    let mut index = 0;
    while index < sidecars.len() {
        let live = sidecars[index]
            .hwnd
            .is_some_and(|hwnd| unsafe { IsWindow(hwnd as HWND) } != 0);
        if live {
            remember(
                failure,
                RuntimeError::new(
                    Kind::HostFailure,
                    "toolbar HWND remains live after worker join; bitmap owner kept process-retained",
                ),
            );
            index += 1;
            continue;
        }
        match sidecars[index].owner.try_retire() {
            Ok(()) => {
                sidecars.remove(index);
            }
            Err(error) => {
                remember(failure, error);
                index += 1;
            }
        }
    }
}

fn keep_cleanup_cause(
    previous: Option<Arc<RuntimeError>>,
    current: RuntimeError,
) -> (Arc<RuntimeError>, RuntimeError) {
    let cause = match previous {
        Some(previous) => {
            let kind = previous.kind().with_cleanup(current.kind());
            RuntimeError::with_source(
                kind,
                "toolbar bitmap cleanup retry failed after an earlier retained error",
                RetainedBitmapCleanupFailure { previous, current },
            )
        }
        None => current,
    };
    let cause = Arc::new(cause);
    let reported = RuntimeError::with_source(
        cause.kind(),
        "toolbar bitmap owner remains process-retained for shutdown retry",
        SharedBitmapFailure(Arc::clone(&cause)),
    );
    (cause, reported)
}

#[derive(Debug)]
struct SharedBitmapFailure(Arc<RuntimeError>);

impl std::fmt::Display for SharedBitmapFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, formatter)
    }
}

impl std::error::Error for SharedBitmapFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[derive(Debug)]
struct RetainedBitmapCleanupFailure {
    previous: Arc<RuntimeError>,
    current: RuntimeError,
}

impl std::fmt::Display for RetainedBitmapCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; retained retry also failed: {}",
            self.previous, self.current
        )
    }
}

impl std::error::Error for RetainedBitmapCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.current)
    }
}

#[derive(Debug)]
pub(super) enum ToolbarBitmapOwner {
    Guest(Win16BitmapLease),
    Owned(usize),
}

pub(super) fn unretained_owner_error(
    primary: RuntimeError,
    retention: RuntimeError,
    owner: ToolbarBitmapOwner,
) -> RuntimeError {
    let kind = primary.kind().with_cleanup(retention.kind());
    RuntimeError::with_source(
        kind,
        "toolbar bitmap cleanup and owner retention both failed",
        UnretainedToolbarOwnerFailure {
            primary,
            retention,
            _owner: owner,
        },
    )
}

#[derive(Debug)]
struct UnretainedToolbarOwnerFailure {
    primary: RuntimeError,
    retention: RuntimeError,
    // Keep the native bitmap alive while this cleanup/retention failure is held.
    _owner: ToolbarBitmapOwner,
}

impl std::fmt::Display for UnretainedToolbarOwnerFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; retention also failed: {}",
            self.primary, self.retention
        )
    }
}

impl std::error::Error for UnretainedToolbarOwnerFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

impl ToolbarBitmapOwner {
    pub(super) fn try_retire(&mut self) -> Result<(), RuntimeError> {
        match self {
            Self::Guest(lease) => lease.try_release(),
            Self::Owned(handle) if *handle == 0 => Ok(()),
            Self::Owned(handle) => {
                // SAFETY: `handle` is owned by this exact toolbar sidecar.
                if unsafe {
                    windows_sys::Win32::Graphics::Gdi::DeleteObject(
                        *handle as windows_sys::Win32::Graphics::Gdi::HGDIOBJ,
                    )
                } == 0
                {
                    return Err(RuntimeError::new(
                        Kind::HostFailure,
                        "DeleteObject failed for toolbar-owned bitmap",
                    ));
                }
                *handle = 0;
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct ToolbarBitmapSidecar {
    pub(super) worker_retirement_id: u64,
    pub(super) operation: u64,
    pub(super) window: Option<Win16HostWindow>,
    pub(super) hwnd: Option<usize>,
    pub(super) expected_parent: usize,
    pub(super) control_id: u16,
    pub(super) subclass_id: usize,
    pub(super) installed: bool,
    pub(super) owner: ToolbarBitmapOwner,
}

// WorkerState transfers any remaining records into its pre-reserved
// WorkerRetention pool before the USER thread exits.

pub(super) fn bind_and_install(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
    window: Option<Win16HostWindow>,
    hwnd: HWND,
) -> Result<(), RuntimeError> {
    if hwnd.is_null() || unsafe { IsWindow(hwnd) } == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "CreateToolbarEx returned an HWND that is no longer live",
        ));
    }
    let (subclass_id, expected_parent, control_id) = {
        let mut worker = state.try_borrow_mut().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap sidecar state is already borrowed",
            )
        })?;
        let sidecar = worker
            .toolbar_bitmap_sidecars
            .iter_mut()
            .find(|entry| entry.operation == operation)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "staged toolbar bitmap owner disappeared after CreateToolbarEx",
                )
            })?;
        if sidecar.hwnd.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap owner was bound to an HWND twice",
            ));
        }
        sidecar.hwnd = Some(hwnd as usize);
        (
            sidecar.subclass_id,
            sidecar.expected_parent,
            sidecar.control_id,
        )
    };
    if unsafe { GetParent(hwnd) } as usize != expected_parent
        || unsafe { GetDlgCtrlID(hwnd) } != i32::from(control_id)
        || !is_toolbar_class(hwnd)
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "CreateToolbarEx result no longer identifies its requested toolbar child",
        ));
    }
    if let Some(window) = window {
        if super::win16_window_identity::resolve(state, window) != Some(hwnd) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap owner does not match its registered window identity",
            ));
        }
    }
    {
        let mut worker = state.try_borrow_mut().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap sidecar state is already borrowed",
            )
        })?;
        let sidecar = worker
            .toolbar_bitmap_sidecars
            .iter_mut()
            .find(|entry| entry.operation == operation && entry.hwnd == Some(hwnd as usize))
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar bitmap owner disappeared before subclass installation",
                )
            })?;
        sidecar.window = window;
    }
    // SAFETY: The operation-owned sidecar stores the exact returned HWND,
    // class, parent, control ID, and unique USER operation identity.
    if unsafe { SetWindowSubclass(hwnd, Some(toolbar_bitmap_subclass_proc), subclass_id, 0) } == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "SetWindowSubclass failed for toolbar bitmap lifetime tracking",
        ));
    }
    let mut worker = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar bitmap sidecar state is already borrowed",
        )
    })?;
    let sidecar = worker
        .toolbar_bitmap_sidecars
        .iter_mut()
        .find(|entry| entry.operation == operation && entry.hwnd == Some(hwnd as usize))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap owner disappeared during subclass installation",
            )
        })?;
    sidecar.installed = true;
    Ok(())
}

pub(super) fn retire_failed_create(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
) -> Result<(), RuntimeError> {
    retire_operation(state, operation)
}

pub(super) fn retire_destroyed(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
) -> Result<(), RuntimeError> {
    let present = state
        .try_borrow()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap sidecar state is already borrowed",
            )
        })?
        .toolbar_bitmap_sidecars
        .iter()
        .any(|entry| entry.operation == operation);
    if !present {
        return Ok(());
    }
    let live = state
        .try_borrow()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap sidecar state is already borrowed",
            )
        })?
        .toolbar_bitmap_sidecars
        .iter()
        .find(|entry| entry.operation == operation)
        .and_then(|entry| entry.hwnd)
        .is_some_and(|hwnd| unsafe { IsWindow(hwnd as HWND) } != 0);
    if live {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "toolbar bitmap owner cannot retire while its HWND remains live",
        ));
    }
    retire_operation(state, operation)
}

pub(super) fn destroy_orphan(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
    hwnd: HWND,
) -> Result<(), RuntimeError> {
    let exact = state
        .try_borrow()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap sidecar state is already borrowed",
            )
        })?
        .toolbar_bitmap_sidecars
        .iter()
        .find(|entry| entry.operation == operation)
        .is_some_and(|entry| {
            entry.window.is_none()
                && entry.hwnd == Some(hwnd as usize)
                && entry.expected_parent == unsafe { GetParent(hwnd) } as usize
                && i32::from(entry.control_id) == unsafe { GetDlgCtrlID(hwnd) }
                && is_toolbar_class(hwnd)
        });
    if !exact {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "cannot destroy an unregistered toolbar without its exact child identity",
        ));
    }
    // SAFETY: The HWND is the exact direct CreateToolbarEx result retained by
    // the staged owner and still matches its original parent, ID and class.
    if unsafe { DestroyWindow(hwnd) } == 0 && unsafe { IsWindow(hwnd) } != 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "DestroyWindow failed for an unregistered toolbar result",
        ));
    }
    Ok(())
}

pub(super) fn retire_all(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    let count = state
        .try_borrow()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap sidecar state is already borrowed",
            )
        })?
        .toolbar_bitmap_sidecars
        .len();
    let mut operations = Vec::new();
    operations.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "snapshot toolbar bitmap owners for shutdown",
            error,
        )
    })?;
    operations.extend(
        state
            .borrow()
            .toolbar_bitmap_sidecars
            .iter()
            .map(|entry| entry.operation),
    );
    let mut failure = None;
    for operation in operations {
        let record = state.try_borrow().ok().and_then(|worker| {
            worker
                .toolbar_bitmap_sidecars
                .iter()
                .find(|entry| entry.operation == operation)
                .map(|entry| {
                    (
                        entry.window,
                        entry.hwnd,
                        entry.expected_parent,
                        entry.control_id,
                    )
                })
        });
        let Some((window, hwnd, parent, control_id)) = record else {
            continue;
        };
        if let Some(hwnd) = hwnd
            .map(|value| value as HWND)
            .filter(|hwnd| unsafe { IsWindow(*hwnd) } != 0)
        {
            let exact = window.is_some_and(|token| {
                super::win16_window_identity::resolve(state, token) == Some(hwnd)
            });
            let orphan_is_exact_child = window.is_none()
                && hwnd as usize != parent
                && unsafe { GetParent(hwnd) } as usize == parent
                && unsafe { GetDlgCtrlID(hwnd) } == i32::from(control_id)
                && is_toolbar_class(hwnd);
            if !exact && !orphan_is_exact_child {
                remember(
                    &mut failure,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "live toolbar bitmap owner lost its exact HWND or child identity",
                    ),
                );
                continue;
            }
            // SAFETY: Either the stored generation token resolves to this
            // HWND, or this is the still-live child returned by our API call.
            if unsafe { DestroyWindow(hwnd) } == 0 && unsafe { IsWindow(hwnd) } != 0 {
                remember(
                    &mut failure,
                    RuntimeError::new(
                        Kind::HostFailure,
                        "DestroyWindow failed while retiring a toolbar bitmap owner",
                    ),
                );
                continue;
            }
        }
        let still_owned = state.try_borrow().ok().is_some_and(|worker| {
            worker
                .toolbar_bitmap_sidecars
                .iter()
                .any(|entry| entry.operation == operation)
        });
        if !still_owned {
            continue;
        }
        if let Err(error) = retire_operation(state, operation) {
            remember(&mut failure, error);
        }
    }
    failure.map_or(Ok(()), Err)
}

/// A native API return plus an invalid HWND is the destruction proof. Merely
/// receiving WM_NCDESTROY is not enough because guest code can send that value.
pub(super) fn retire_destroyed_windows(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<(), RuntimeError> {
    let count = state
        .try_borrow()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap sidecar state is already borrowed",
            )
        })?
        .toolbar_bitmap_sidecars
        .len();
    let mut operations = Vec::new();
    operations.try_reserve_exact(count).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "snapshot toolbar HWNDs after native USER return",
            error,
        )
    })?;
    {
        let worker = state.try_borrow().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap sidecar state is already borrowed",
            )
        })?;
        for sidecar in &worker.toolbar_bitmap_sidecars {
            if sidecar
                .hwnd
                .is_some_and(|hwnd| unsafe { IsWindow(hwnd as HWND) } == 0)
            {
                operations.push(sidecar.operation);
            }
        }
    }
    let mut failure = None;
    for operation in operations {
        if let Err(error) = retire_operation(state, operation) {
            remember(&mut failure, error);
        }
    }
    failure.map_or(Ok(()), Err)
}

fn retire_operation(state: &Rc<RefCell<WorkerState>>, operation: u64) -> Result<(), RuntimeError> {
    let mut worker = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar bitmap sidecar state is already borrowed",
        )
    })?;
    let index = worker
        .toolbar_bitmap_sidecars
        .iter()
        .position(|entry| entry.operation == operation)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap owner operation is not registered",
            )
        })?;
    if worker.toolbar_bitmap_sidecars[index]
        .hwnd
        .is_some_and(|hwnd| unsafe { IsWindow(hwnd as HWND) } != 0)
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "cannot release a toolbar bitmap while its exact HWND is still live",
        ));
    }
    worker.toolbar_bitmap_sidecars[index].owner.try_retire()?;
    worker.toolbar_bitmap_sidecars.remove(index);
    worker
        .toolbar_bitmap_retention
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .cancel_slots(1)?;
    Ok(())
}

unsafe extern "system" fn toolbar_bitmap_subclass_proc(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    subclass_id: usize,
    _reference_data: usize,
) -> LRESULT {
    let forwarded = std::cell::Cell::new(None);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if message != WM_NCDESTROY {
            // SAFETY: This is the standard subclass forwarding path.
            return unsafe { DefSubclassProc(hwnd, message, w_param, l_param) };
        }
        let Some(state) = win16_window_worker::worker_context() else {
            // SAFETY: Preserve the native control's teardown even if worker TLS
            // was unexpectedly retired before the HWND.
            return unsafe { DefSubclassProc(hwnd, message, w_param, l_param) };
        };
        let matched = state.try_borrow().ok().is_some_and(|worker| {
            worker.toolbar_bitmap_sidecars.iter().any(|entry| {
                entry.hwnd == Some(hwnd as usize)
                    && entry.subclass_id == subclass_id
                    && entry.installed
            })
        });
        if !matched {
            let native = unsafe { DefSubclassProc(hwnd, message, w_param, l_param) };
            forwarded.set(Some(native));
            super::win16_window_callbacks::fail_worker(
                &state,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar WM_NCDESTROY has no matching installed bitmap pin",
                ),
            );
            return native;
        };
        let removed =
            unsafe { RemoveWindowSubclass(hwnd, Some(toolbar_bitmap_subclass_proc), subclass_id) }
                != 0;
        let native = unsafe { DefSubclassProc(hwnd, message, w_param, l_param) };
        forwarded.set(Some(native));
        let removal = if removed {
            Ok(())
        } else {
            Err(RuntimeError::new(
                Kind::HostFailure,
                "RemoveWindowSubclass failed at toolbar WM_NCDESTROY",
            ))
        };
        if let Err(error) = removal {
            super::win16_window_callbacks::fail_worker(&state, error);
        }
        native
    }));
    match outcome {
        Ok(result) => result,
        Err(_) => {
            if let Some(state) = win16_window_worker::worker_context() {
                super::win16_window_callbacks::fail_worker(
                    &state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "toolbar bitmap subclass callback panicked",
                    ),
                );
            }
            forwarded
                .get()
                .unwrap_or_else(|| unsafe { DefSubclassProc(hwnd, message, w_param, l_param) })
        }
    }
}

fn is_toolbar_class(hwnd: HWND) -> bool {
    const TOOLBAR_WINDOW32: &[u16] = &[
        b'T' as u16,
        b'o' as u16,
        b'o' as u16,
        b'l' as u16,
        b'b' as u16,
        b'a' as u16,
        b'r' as u16,
        b'W' as u16,
        b'i' as u16,
        b'n' as u16,
        b'd' as u16,
        b'o' as u16,
        b'w' as u16,
        b'3' as u16,
        b'2' as u16,
    ];
    let mut name = [0_u16; 64];
    let count = unsafe { GetClassNameW(hwnd, name.as_mut_ptr(), name.len() as i32) };
    count > 0 && &name[..count as usize] == TOOLBAR_WINDOW32
}

fn remember(failure: &mut Option<RuntimeError>, error: RuntimeError) {
    *failure = Some(match failure.take() {
        None => error,
        Some(primary) => {
            let kind = primary.kind().with_cleanup(error.kind());
            RuntimeError::with_source(
                kind,
                "multiple toolbar bitmap owner cleanups failed",
                ToolbarBitmapCleanupFailure {
                    primary,
                    cleanup: error,
                },
            )
        }
    });
}

#[derive(Debug)]
struct ToolbarBitmapCleanupFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl std::fmt::Display for ToolbarBitmapCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; cleanup also failed: {}", self.primary, self.cleanup)
    }
}

impl std::error::Error for ToolbarBitmapCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
