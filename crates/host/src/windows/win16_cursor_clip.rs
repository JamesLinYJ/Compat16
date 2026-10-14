//! Best-effort cleanup of this USER worker's successful cursor constraints.
//!
//! Win32 exposes a desktop-wide rectangle, not an owner or an atomic
//! compare-and-release operation. Matching observations reduce interference
//! with another application but cannot prove ownership or remove that race.

use std::cell::Cell;
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostRect};
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    ClipCursor, GetClipCursor, GetForegroundWindow, GetWindowThreadProcessId,
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct ForegroundObservation {
    window: usize,
    process: u32,
    thread: u32,
}

#[derive(Clone, Copy)]
struct CleanupObligation {
    sequence: u64,
    rect: Win16HostRect,
    foreground: Option<ForegroundObservation>,
}

thread_local! {
    static SEQUENCE: Cell<Option<u64>> = const { Cell::new(Some(0)) };
    static CLEANUP: Cell<Option<CleanupObligation>> = const { Cell::new(None) };
}

pub(super) struct WorkerExitGuard;

impl Drop for WorkerExitGuard {
    fn drop(&mut self) {
        if let Err(error) = cleanup_for_exit() {
            eprintln!("runtime: cursor clipping cleanup remains incomplete: {error}");
        }
    }
}

pub(super) fn set(rect: Option<Win16HostRect>) -> Result<bool, RuntimeError> {
    // This is a local reentry sequence, not a native desktop ownership token.
    let sequence = SEQUENCE.with(|current| {
        let next = current.get().and_then(|value| value.checked_add(1)).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "cursor clipping call sequence exhausted"))?;
        current.set(Some(next));
        Ok::<_, RuntimeError>(next)
    })?;
    let native = rect.map(|rect| RECT {
        left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
    });
    let succeeded = unsafe {
        ClipCursor(native.as_ref().map_or(std::ptr::null(), |rect| rect)) != 0
    };
    if !succeeded || SEQUENCE.with(Cell::get) != Some(sequence) {
        return Ok(succeeded);
    }
    if rect.is_none() {
        CLEANUP.with(|slot| slot.set(None));
        return Ok(true);
    }
    // USER may clamp a rectangle to the desktop. Retain actual readback, not
    // requested coordinates. A failed read cannot justify a later release.
    let observed = read_clip();
    let foreground = foreground();
    if SEQUENCE.with(Cell::get) != Some(sequence) {
        return Ok(true);
    }
    // A successful new native set supersedes the old obligation, even when
    // its observation fails. Never reuse the old rectangle for cleanup.
    CLEANUP.with(|slot| slot.set(None));
    let foreground = foreground?;
    let Some(rect) = observed else {
        return Err(RuntimeError::new(Kind::HostFailure,
            "cursor clipping succeeded but its cleanup rectangle could not be read"));
    };
    CLEANUP.with(|slot| slot.set(Some(CleanupObligation { sequence, rect, foreground })));
    Ok(true)
}

/// A foreground handoff invalidates prior observations; never release a
/// subsequently established constraint merely because its rectangle is equal.
pub(super) fn forget_after_deactivation() {
    SEQUENCE.with(|current| current.set(current.get().and_then(|value| value.checked_add(1))));
    CLEANUP.with(|slot| slot.set(None));
}

/// Called before terminal worker cleanup and again by the local thread guard.
/// Failure keeps the observation for a later shutdown attempt. No operation
/// runs for workers which have never successfully installed a constraint.
pub(super) fn cleanup_for_exit() -> Result<(), RuntimeError> {
    let Some(observed) = CLEANUP.with(Cell::get) else { return Ok(()); };
    // Terminal cleanup cannot start another guest callback on a client which
    // is already waiting for Abort/Shutdown rather than a USER operation.
    if let Some(state) = super::win16_window_worker::worker_context() {
        state.try_borrow_mut().map_err(|_| RuntimeError::new(Kind::HostFailure,
            "cursor cleanup cannot close guest callbacks during a worker borrow"))?
            .callbacks_enabled = false;
    }
    if foreground()? != observed.foreground {
        forget_if_current(observed.sequence);
        return Ok(());
    }
    let current = read_clip().ok_or_else(|| RuntimeError::new(Kind::HostFailure,
        "read the cursor constraint before worker exit"))?;
    if current != observed.rect {
        forget_if_current(observed.sequence);
        return Ok(());
    }
    if !CLEANUP.with(|slot| slot.get().is_some_and(|value| value.sequence == observed.sequence)) {
        return Ok(());
    }
    // There is no public atomic compare-and-release. Another process can
    // still replace the global rectangle between this read and ClipCursor.
    if unsafe { ClipCursor(std::ptr::null()) } == 0 {
        return Err(RuntimeError::new(Kind::HostFailure,
            "release the observed cursor constraint before worker exit"));
    }
    forget_if_current(observed.sequence);
    Ok(())
}

fn forget_if_current(sequence: u64) {
    CLEANUP.with(|slot| {
        if slot.get().is_some_and(|value| value.sequence == sequence) {
            slot.set(None);
        }
    });
}

fn read_clip() -> Option<Win16HostRect> {
    let mut rect = RECT::default();
    (unsafe { GetClipCursor(&mut rect) } != 0).then_some(Win16HostRect {
        left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
    })
}

fn foreground() -> Result<Option<ForegroundObservation>, RuntimeError> {
    let window = unsafe { GetForegroundWindow() };
    if window.is_null() { return Ok(None); }
    let mut process = 0;
    let thread = unsafe { GetWindowThreadProcessId(window, &mut process) };
    if thread == 0 || process == 0 {
        return Err(RuntimeError::new(Kind::HostFailure,
            "observe the foreground window for cursor constraint cleanup"));
    }
    Ok(Some(ForegroundObservation {
        window: window as usize, process, thread,
    }))
}
