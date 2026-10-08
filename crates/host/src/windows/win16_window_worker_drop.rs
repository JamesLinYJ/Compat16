//! Native drop ownership, queue identity and retirement receipts.

use runtime::{RuntimeError, Win16HostWindow};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::HWND;

/// Full native MSG identity used to keep a no-remove WM_DROPFILES peek paired
/// with the exact HDROP lease until USER removes that queue record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(in crate::windows::win16_windows) struct NativeDropQueueKey {
    pub(in crate::windows::win16_windows) hwnd: usize,
    pub(in crate::windows::win16_windows) message: u32,
    pub(in crate::windows::win16_windows) w_param: usize,
    pub(in crate::windows::win16_windows) l_param: isize,
    pub(in crate::windows::win16_windows) time: u32,
    pub(in crate::windows::win16_windows) x: i32,
    pub(in crate::windows::win16_windows) y: i32,
}

impl NativeDropQueueKey {
    pub(in crate::windows::win16_windows) fn from_msg(
        message: &windows_sys::Win32::UI::WindowsAndMessaging::MSG,
    ) -> Self {
        Self {
            hwnd: message.hwnd as usize,
            message: message.message,
            w_param: message.wParam,
            l_param: message.lParam,
            time: message.time,
            x: message.pt.x,
            y: message.pt.y,
        }
    }
}

/// A WM_DROPFILES HDROP is transferred to the receiver and must be released
/// once with DragFinish. This owner never crosses the host/runtime boundary.
pub(in crate::windows::win16_windows) struct NativeDropOwner(usize);

impl NativeDropOwner {
    pub(in crate::windows::win16_windows) fn new(handle: usize) -> Self {
        Self(handle)
    }

    pub(in crate::windows::win16_windows) fn finish(&mut self) {
        if self.0 != 0 {
            // SAFETY: this value is the sole host-side owner of the exact
            // HDROP transferred by USER or moved from its queue ledger.
            unsafe {
                windows_sys::Win32::UI::Shell::DragFinish(
                    self.0 as windows_sys::Win32::UI::Shell::HDROP,
                );
            }
            self.0 = 0;
        }
    }
}

impl Drop for NativeDropOwner {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Worker-owned transport for native HDROP retirement. Receipts stay at the
/// front until runtime confirms that the exact lease was retired; reserving a
/// slot before ledger claim makes publication infallible after ownership moves.
#[derive(Default)]
pub(in crate::windows::win16_windows) struct NativeDropRetirementQueue {
    receipts: VecDeque<runtime::Win16HostDropRetirementReceipt>,
    reserved: usize,
    last_acknowledged: Option<runtime::Win16HostDropRetirementReceipt>,
}

pub(in crate::windows::win16_windows) type NativeDropRetirementQueueHandle =
    Arc<Mutex<NativeDropRetirementQueue>>;

impl NativeDropRetirementQueue {
    pub(in crate::windows::win16_windows) fn shared() -> NativeDropRetirementQueueHandle {
        Arc::new(Mutex::new(Self::default()))
    }

    pub(in crate::windows::win16_windows) fn reserve(
        queue_handle: &NativeDropRetirementQueueHandle,
    ) -> Result<NativeDropRetirementReservation, RuntimeError> {
        let mut queue = lock_native_drop_retirements(queue_handle);
        let required = queue
            .receipts
            .len()
            .checked_add(queue.reserved)
            .and_then(|reserved| reserved.checked_add(1))
            .ok_or_else(|| {
                RuntimeError::new(
                    runtime::DiagnosticKind::ResourceExhausted,
                    "native WM_DROPFILES retirement reservation count overflow",
                )
            })?;
        if queue.receipts.capacity() < required {
            let additional = required - queue.receipts.len();
            queue.receipts.try_reserve(additional).map_err(|error| {
                RuntimeError::with_source(
                    runtime::DiagnosticKind::ResourceExhausted,
                    "reserve native WM_DROPFILES retirement receipt",
                    error,
                )
            })?;
        }
        queue.reserved += 1;
        Ok(NativeDropRetirementReservation {
            queue: Arc::clone(queue_handle),
            active: true,
        })
    }

    pub(in crate::windows::win16_windows) fn peek(
        queue: &NativeDropRetirementQueueHandle,
    ) -> Option<runtime::Win16HostDropRetirementReceipt> {
        lock_native_drop_retirements(queue)
            .receipts
            .front()
            .copied()
    }

    pub(in crate::windows::win16_windows) fn acknowledge(
        queue: &NativeDropRetirementQueueHandle,
        receipt: runtime::Win16HostDropRetirementReceipt,
    ) -> Result<(), RuntimeError> {
        let mut queue = lock_native_drop_retirements(queue);
        let Some(index) = queue
            .receipts
            .iter()
            .position(|pending| *pending == receipt)
        else {
            // Only an exact retry of the most recently acknowledged receipt
            // is idempotent. Unknown, stale, or wrong-window generations are
            // protocol errors; they cannot silently acknowledge another owner.
            if queue.last_acknowledged == Some(receipt) {
                return Ok(());
            }
            return Err(RuntimeError::new(
                runtime::DiagnosticKind::InternalInvariant,
                "native WM_DROPFILES acknowledgement did not name a pending or last-acknowledged exact receipt",
            ));
        };
        if index != 0 {
            return Err(RuntimeError::new(
                runtime::DiagnosticKind::InternalInvariant,
                "native WM_DROPFILES retirement acknowledgement skipped the FIFO head",
            ));
        }
        queue.receipts.pop_front();
        queue.last_acknowledged = Some(receipt);
        Ok(())
    }
}

fn lock_native_drop_retirements(
    queue: &NativeDropRetirementQueueHandle,
) -> std::sync::MutexGuard<'_, NativeDropRetirementQueue> {
    queue
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(in crate::windows::win16_windows) struct NativeDropRetirementReservation {
    queue: NativeDropRetirementQueueHandle,
    active: bool,
}

impl NativeDropRetirementReservation {
    pub(in crate::windows::win16_windows) fn publish(
        mut self,
        receipt: runtime::Win16HostDropRetirementReceipt,
    ) {
        let mut queue = lock_native_drop_retirements(&self.queue);
        debug_assert!(queue.reserved > 0);
        queue.reserved = queue.reserved.saturating_sub(1);
        // Capacity was reserved for every pending receipt plus every live
        // reservation, so this push cannot allocate after the ledger claim.
        queue.receipts.push_back(receipt);
        self.active = false;
    }
}

impl Drop for NativeDropRetirementReservation {
    fn drop(&mut self) {
        if self.active {
            let mut queue = lock_native_drop_retirements(&self.queue);
            queue.reserved = queue.reserved.saturating_sub(1);
            self.active = false;
        }
    }
}

pub(in crate::windows::win16_windows) struct NativeDropCallbackClaim {
    pub(in crate::windows::win16_windows) delivery: runtime::Win16HostQueuedDropFiles,
    owner: NativeDropOwner,
}

pub(in crate::windows::win16_windows) enum NativeDropCallbackResolution {
    /// This callback's HDROP has no earlier PM_NOREMOVE/native FIFO lease.
    Unqueued,
    /// The lease belongs to the exact currently cookie-bound HWND generation.
    ExactLive(NativeDropCallbackClaim),
    /// The callback's HDROP was already owned by a lease, but its HWND cookie
    /// is no longer live. The caller must release this claim and suppress
    /// guest dispatch; it must never create a second raw HDROP owner.
    StaleLease(NativeDropCallbackClaim),
}

impl NativeDropCallbackClaim {
    pub(in crate::windows::win16_windows) fn finish(&mut self) {
        self.owner.finish();
    }
}

struct NativeDropQueueEntry {
    lease: runtime::Win16HostDropFilesLease,
    window: Win16HostWindow,
    files: runtime::Win16HostDropFiles,
    owner: NativeDropOwner,
}

/// Repeated PM_NOREMOVE calls reuse one immutable file snapshot and lease.
/// PM_REMOVE drops its native owner after copying the snapshot into the result.
#[derive(Default)]
pub(in crate::windows::win16_windows) struct NativeDropFilesQueue {
    entries: HashMap<NativeDropQueueKey, NativeDropQueueEntry>,
}

impl NativeDropFilesQueue {
    /// Retain a WM_DROPFILES owner when a nested native pump has already
    /// removed the MSG before the main message loop sees it. The full MSG key
    /// lets the later FIFO PM_REMOVE reuse this lease and release this owner
    /// exactly once. `owner` is constructed before snapshotting so every error
    /// path releases a handle that has already left USER's queue.
    pub(in crate::windows::win16_windows) fn retain_removed(
        &mut self,
        message: &windows_sys::Win32::UI::WindowsAndMessaging::MSG,
        window: Win16HostWindow,
        hdrop: usize,
        allocate_lease: impl FnOnce() -> Result<u64, RuntimeError>,
        snapshot: impl FnOnce() -> Result<runtime::Win16HostDropFiles, RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let key = NativeDropQueueKey::from_msg(message);
        if let Some(entry) = self.entries.get(&key) {
            if entry.window != window {
                return Err(RuntimeError::new(
                    runtime::DiagnosticKind::InternalInvariant,
                    "deferred WM_DROPFILES identity changed its mapped HWND generation",
                ));
            }
            if entry.lease.0 == 0 || key.w_param != hdrop {
                return Err(RuntimeError::new(
                    runtime::DiagnosticKind::InternalInvariant,
                    "deferred WM_DROPFILES exact queue lease changed its HDROP identity",
                ));
            }
            return Ok(());
        }

        // This MSG was already removed by the nested pump. Install RAII
        // ownership before any allocation or copy can fail.
        let owner = NativeDropOwner::new(hdrop);
        self.entries.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                runtime::DiagnosticKind::ResourceExhausted,
                "reserve deferred native WM_DROPFILES queue lease",
                error,
            )
        })?;
        let files = snapshot()?;
        let lease_id = allocate_lease()?;
        if lease_id == 0 {
            return Err(RuntimeError::new(
                runtime::DiagnosticKind::ResourceExhausted,
                "deferred native WM_DROPFILES queue lease allocator returned reserved identity zero",
            ));
        }
        self.entries.insert(
            key,
            NativeDropQueueEntry {
                lease: runtime::Win16HostDropFilesLease(lease_id),
                window,
                files,
                owner,
            },
        );
        Ok(())
    }

    /// A native modal pump can remove a WM_DROPFILES MSG and invoke its
    /// WndProc/DLGPROC without passing through our GetMessage/PeekMessage
    /// adapter. Claim the exact HWND/HDROP queue record before snapshotting so
    /// the callback and PM_NOREMOVE ledger never own the same native handle.
    pub(in crate::windows::win16_windows) fn claim_callback(
        &mut self,
        hwnd: HWND,
        hdrop: usize,
        window: Win16HostWindow,
    ) -> Result<Option<NativeDropCallbackClaim>, RuntimeError> {
        let mut matched_key = None;
        for (key, entry) in &self.entries {
            if key.hwnd == hwnd as usize
                && key.message == 0x0233
                && key.w_param == hdrop
                && entry.window == window
            {
                if matched_key.replace(*key).is_some() {
                    return Err(RuntimeError::new(
                        runtime::DiagnosticKind::InternalInvariant,
                        "one WM_DROPFILES callback matched multiple exact native queue leases",
                    ));
                }
            }
        }
        let Some(key) = matched_key else {
            return Ok(None);
        };
        let entry = self.entries.remove(&key).ok_or_else(|| {
            RuntimeError::new(
                runtime::DiagnosticKind::InternalInvariant,
                "WM_DROPFILES queue lease disappeared during callback handoff",
            )
        })?;
        let result = NativeDropCallbackClaim {
            delivery: runtime::Win16HostQueuedDropFiles {
                lease: entry.lease,
                native_removed: true,
                files: entry.files.clone(),
            },
            owner: entry.owner,
        };
        Ok(Some(result))
    }

    pub(in crate::windows::win16_windows) fn callback_window(
        &self,
        hwnd: HWND,
        hdrop: usize,
    ) -> Result<Option<Win16HostWindow>, RuntimeError> {
        let mut matched = None;
        for (key, entry) in &self.entries {
            if key.hwnd == hwnd as usize && key.message == 0x0233 && key.w_param == hdrop {
                if matched.replace(entry.window).is_some() {
                    return Err(RuntimeError::new(
                        runtime::DiagnosticKind::InternalInvariant,
                        "one WM_DROPFILES callback matched multiple exact native queue leases",
                    ));
                }
            }
        }
        Ok(matched)
    }

    pub(in crate::windows::win16_windows) fn expose(
        &mut self,
        message: &windows_sys::Win32::UI::WindowsAndMessaging::MSG,
        window: Win16HostWindow,
        hdrop: usize,
        removed: bool,
        allocate_lease: impl FnOnce() -> Result<u64, RuntimeError>,
        snapshot: impl FnOnce() -> Result<runtime::Win16HostDropFiles, RuntimeError>,
    ) -> Result<runtime::Win16HostQueuedDropFiles, RuntimeError> {
        let key = NativeDropQueueKey::from_msg(message);
        if let Some(entry) = self.entries.get(&key) {
            if entry.window != window {
                return Err(RuntimeError::new(
                    runtime::DiagnosticKind::InternalInvariant,
                    "queued WM_DROPFILES identity changed its mapped HWND generation",
                ));
            }
            let result = runtime::Win16HostQueuedDropFiles {
                lease: entry.lease,
                native_removed: removed,
                files: entry.files.clone(),
            };
            if removed {
                self.entries.remove(&key);
            }
            return Ok(result);
        }

        // A removing queue read has transferred HDROP before we copy it, so
        // install its RAII owner first. A no-remove read has not transferred
        // ownership and leaves HDROP on the native queue if copying fails.
        let removed_owner = removed.then(|| NativeDropOwner::new(hdrop));
        let files = snapshot()?;
        let lease_id = allocate_lease()?;
        if lease_id == 0 {
            return Err(RuntimeError::new(
                runtime::DiagnosticKind::ResourceExhausted,
                "native WM_DROPFILES queue lease allocator returned reserved identity zero",
            ));
        }
        let lease = runtime::Win16HostDropFilesLease(lease_id);
        if !removed {
            self.entries.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    runtime::DiagnosticKind::ResourceExhausted,
                    "reserve native WM_DROPFILES queue lease",
                    error,
                )
            })?;
        }
        let result = runtime::Win16HostQueuedDropFiles {
            lease,
            native_removed: removed,
            files: files.clone(),
        };
        if !removed {
            self.entries.insert(
                key,
                NativeDropQueueEntry {
                    lease,
                    window,
                    files,
                    owner: NativeDropOwner::new(hdrop),
                },
            );
        } else {
            // The removed MSG transferred HDROP ownership to this call. The
            // snapshot has been copied, so release before returning it.
            drop(removed_owner);
        }
        Ok(result)
    }

    pub(in crate::windows::win16_windows) fn retire_window(&mut self, window: Win16HostWindow) {
        self.entries.retain(|_, entry| entry.window != window);
    }

    pub(in crate::windows::win16_windows) fn retirement_for_message(
        &self,
        message: &windows_sys::Win32::UI::WindowsAndMessaging::MSG,
    ) -> Result<Option<runtime::Win16HostDropRetirementReceipt>, RuntimeError> {
        let Some(entry) = self.entries.get(&NativeDropQueueKey::from_msg(message)) else {
            return Ok(None);
        };
        if entry.lease.0 == 0 || entry.window.0 == 0 {
            return Err(RuntimeError::new(
                runtime::DiagnosticKind::InternalInvariant,
                "native WM_DROPFILES ledger entry has a reserved retirement identity",
            ));
        }
        Ok(Some(runtime::Win16HostDropRetirementReceipt {
            lease: entry.lease,
            window: entry.window,
        }))
    }

    pub(in crate::windows::win16_windows) fn retire_message(
        &mut self,
        message: &windows_sys::Win32::UI::WindowsAndMessaging::MSG,
    ) -> Result<Option<runtime::Win16HostDropRetirementReceipt>, RuntimeError> {
        let key = NativeDropQueueKey::from_msg(message);
        let expected = self.retirement_for_message(message)?;
        let Some(expected) = expected else {
            return Ok(None);
        };
        let Some(entry) = self.entries.get(&key) else {
            return Err(RuntimeError::new(
                runtime::DiagnosticKind::InternalInvariant,
                "native WM_DROPFILES ledger entry disappeared before its exact retirement claim",
            ));
        };
        let current = runtime::Win16HostDropRetirementReceipt {
            lease: entry.lease,
            window: entry.window,
        };
        if current != expected {
            return Err(RuntimeError::new(
                runtime::DiagnosticKind::InternalInvariant,
                "native WM_DROPFILES ledger retirement changed its exact pre-reserved identity",
            ));
        }
        let entry = self.entries.remove(&key).ok_or_else(|| {
            RuntimeError::new(
                runtime::DiagnosticKind::InternalInvariant,
                "native WM_DROPFILES ledger entry disappeared during its exact retirement claim",
            )
        })?;
        drop(entry);
        Ok(Some(expected))
    }

    pub(in crate::windows::win16_windows) fn retire_all(&mut self) {
        self.entries.clear();
    }
}
