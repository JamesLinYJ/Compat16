//! Native `timeSetEvent` / `timeKillEvent` trampoline.
//!
//! The WinMM callback receives an opaque token. The guest FAR procedure stays
//! in the runtime registration and is never stored in this table or passed to
//! WinMM as a function pointer.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16GuestCallbackEvent, Win16GuestCallbackSender,
    Win16GuestCallbackToken, multimedia_timer_callback_arguments,
};
use windows_sys::Win32::Media::{TIME_ONESHOT, TIME_PERIODIC, timeKillEvent, timeSetEvent};

const TIMERR_NOCANDO: u32 = 97;

#[derive(Clone)]
struct TimerSlot {
    sender: Win16GuestCallbackSender,
    callback: Win16GuestCallbackToken,
    guest_timer: u16,
    user: u32,
    one_shot: bool,
}

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static TIMERS: Mutex<BTreeMap<u64, TimerSlot>> = Mutex::new(BTreeMap::new());

fn timers() -> std::sync::MutexGuard<'static, BTreeMap<u64, TimerSlot>> {
    TIMERS.lock().unwrap_or_else(|poison| poison.into_inner())
}

pub(super) fn set_event(
    owned: &mut BTreeMap<u32, u64>,
    sender: &Win16GuestCallbackSender,
    delay: u16,
    resolution: u16,
    user: u32,
    periodic: bool,
    callback: Win16GuestCallbackToken,
    guest_timer: u16,
) -> Result<Option<u32>, RuntimeError> {
    let token = NEXT_TOKEN
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native multimedia timer tokens are exhausted",
            )
        })?;
    {
        let mut table = timers();
        // A completed one-shot drops its slot before the runtime kills it.
        // Drop that stale native id so WinMM may reuse it.
        owned.retain(|_, existing| table.contains_key(existing));
        table.insert(
            token,
            TimerSlot {
                sender: sender.clone(),
                callback,
                guest_timer,
                user,
                one_shot: !periodic,
            },
        );
    }
    let flags = if periodic {
        TIME_PERIODIC
    } else {
        TIME_ONESHOT
    };
    // SAFETY: the trampoline is a static function. `token` is an integer key
    // into the host table, not a guest address and not a host pointer passed
    // back to the guest. WinMM retains no caller buffer.
    let native = unsafe {
        timeSetEvent(
            u32::from(delay),
            u32::from(resolution),
            Some(multimedia_timer_callback),
            token as usize,
            flags,
        )
    };
    if native == 0 {
        timers().remove(&token);
        return Ok(None);
    }
    if owned.contains_key(&native) {
        timers().remove(&token);
        // SAFETY: this id was just returned by timeSetEvent and is not recorded.
        let _ = unsafe { timeKillEvent(native) };
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "WinMM reused a multimedia timer id that is still owned",
        ));
    }
    owned.insert(native, token);
    Ok(Some(native))
}

pub(super) fn kill_event(owned: &mut BTreeMap<u32, u64>, native: u32) -> u32 {
    let Some(token) = owned.remove(&native) else {
        return TIMERR_NOCANDO;
    };
    let removed = timers().remove(&token).is_some();
    // SAFETY: `native` is the id previously returned by timeSetEvent for this token.
    let _ = unsafe { timeKillEvent(native) };
    if removed { 0 } else { TIMERR_NOCANDO }
}

pub(super) fn retire_events(
    owned: &mut BTreeMap<u32, u64>,
    first_error: &mut Option<RuntimeError>,
) {
    for (native, token) in std::mem::take(owned) {
        timers().remove(&token);
        // SAFETY: each id in this table was returned by timeSetEvent.
        let result = unsafe { timeKillEvent(native) };
        if result != 0 && result != TIMERR_NOCANDO {
            if first_error.is_none() {
                *first_error = Some(RuntimeError::new(
                    Kind::HostFailure,
                    format!("native timeKillEvent failed during host teardown (0x{result:08X})"),
                ));
            }
        }
    }
}

/// WinMM invokes this on a timer thread. It publishes owned callback values
/// and returns; it does not enter guest code.
unsafe extern "system" fn multimedia_timer_callback(
    _timer_id: u32,
    _message: u32,
    user: usize,
    _reserved1: usize,
    _reserved2: usize,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let token = user as u64;
        let slot = {
            let mut table = timers();
            let slot = table.get(&token).cloned();
            if slot.as_ref().is_some_and(|slot| slot.one_shot) {
                table.remove(&token);
            }
            slot
        };
        let Some(slot) = slot else { return };
        let _ = slot.sender.try_send(Win16GuestCallbackEvent {
            callback: slot.callback,
            arguments: multimedia_timer_callback_arguments(slot.guest_timer, slot.user).to_vec(),
        });
    }));
}
