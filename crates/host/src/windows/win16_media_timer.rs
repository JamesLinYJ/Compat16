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
use windows_sys::Win32::Media::{
    TIME_KILL_SYNCHRONOUS, TIME_ONESHOT, TIME_PERIODIC, timeKillEvent, timeSetEvent,
};

const TIMERR_NOCANDO: u32 = 97;

#[derive(Clone)]
struct TimerSlot {
    sender: Win16GuestCallbackSender,
    callback: Win16GuestCallbackToken,
    guest_timer: u16,
    user: u32,
    one_shot: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OwnedTimer {
    native: u32,
    token: u64,
}

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static TIMERS: Mutex<BTreeMap<u64, TimerSlot>> = Mutex::new(BTreeMap::new());
// Serialize native creation/cancellation across host owners so a completed
// one-shot id cannot be recycled by another owner during a cancellation check.
// Callback threads use only TIMERS, never this control lock.
static CONTROL: Mutex<()> = Mutex::new(());

fn timers() -> std::sync::MutexGuard<'static, BTreeMap<u64, TimerSlot>> {
    TIMERS.lock().unwrap_or_else(|poison| poison.into_inner())
}

pub(super) fn set_event(
    owned: &mut BTreeMap<u32, OwnedTimer>,
    sender: &Win16GuestCallbackSender,
    delay: u16,
    resolution: u16,
    user: u32,
    periodic: bool,
    callback: Win16GuestCallbackToken,
    guest_timer: u16,
) -> Result<Option<u32>, RuntimeError> {
    let _control = CONTROL.lock().unwrap_or_else(|poison| poison.into_inner());
    let token = NEXT_TOKEN
        .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current <= u64::from(u32::MAX)).then(|| current + 1)
        })
        .map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "native multimedia timer tokens are exhausted",
            )
        })?;
    {
        let mut table = timers();
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
    let flags = TIME_KILL_SYNCHRONOUS
        | if periodic {
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
    // Runtime identities must not be recycled WinMM ids: a queued one-shot
    // callback may outlive its native id and overlap a later timer using it.
    let identity = token as u32;
    owned.insert(identity, OwnedTimer { native, token });
    Ok(Some(identity))
}

pub(super) fn kill_event(owned: &mut BTreeMap<u32, OwnedTimer>, identity: u32) -> u32 {
    kill_event_with(owned, identity, |id| {
        // SAFETY: the owner and callback token were checked below. Synchronous
        // cancellation completes any callback without holding the table lock.
        unsafe { timeKillEvent(id) }
    })
}

fn kill_event_with(
    owned: &mut BTreeMap<u32, OwnedTimer>,
    identity: u32,
    cancel: impl FnOnce(u32) -> u32,
) -> u32 {
    let _control = CONTROL.lock().unwrap_or_else(|poison| poison.into_inner());
    let Some(&OwnedTimer { native, token }) = owned.get(&identity) else {
        return TIMERR_NOCANDO;
    };
    // A one-shot removes its slot only after publication has completed. Its
    // obsolete native id may already belong to another timer; do not cancel it.
    if !timers().contains_key(&token) {
        owned.remove(&identity);
        return 0;
    }
    let result = cancel(native);
    let mut table = timers();
    if result == 0 || !table.contains_key(&token) {
        table.remove(&token);
        owned.remove(&identity);
        0
    } else {
        // The producer can still publish. Keep both owners for a later retry.
        result
    }
}

pub(super) fn retire_events(
    owned: &mut BTreeMap<u32, OwnedTimer>,
    first_error: &mut Option<RuntimeError>,
) {
    let natives: Vec<_> = owned.keys().copied().collect();
    for native in natives {
        let result = kill_event(owned, native);
        if result != 0 {
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
// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn multimedia_timer_callback(
    _timer_id: u32,
    _message: u32,
    user: usize,
    _reserved1: usize,
    _reserved2: usize,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let token = user as u64;
        let slot = timers().get(&token).cloned();
        let Some(slot) = slot else { return };
        let _ = slot.sender.try_send(Win16GuestCallbackEvent {
            callback: slot.callback,
            arguments: multimedia_timer_callback_arguments(slot.guest_timer, slot.user).to_vec(),
        });
        if slot.one_shot {
            timers().remove(&token);
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> (BTreeMap<u32, OwnedTimer>, u64) {
        let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
        let (sender, _receiver) = runtime::win16_guest_callback_channel(1).unwrap();
        timers().insert(
            token,
            TimerSlot {
                sender,
                callback: Win16GuestCallbackToken(token),
                guest_timer: 1,
                user: 0,
                one_shot: false,
            },
        );
        (
            BTreeMap::from([(1, OwnedTimer { native: 42, token })]),
            token,
        )
    }

    #[test]
    fn failed_native_cancel_retains_both_owners_until_retry() {
        let (mut owned, token) = owner();
        assert_eq!(kill_event_with(&mut owned, 1, |_| 11), 11);
        assert_eq!(owned.get(&1).map(|entry| entry.token), Some(token));
        assert!(timers().contains_key(&token));
        assert_eq!(
            kill_event_with(&mut owned, 1, |native| {
                assert_eq!(native, 42);
                0
            }),
            0
        );
        assert!(owned.is_empty());
        assert!(!timers().contains_key(&token));
    }

    #[test]
    fn completed_one_shot_does_not_cancel_a_recycled_native_id() {
        let (mut owned, token) = owner();
        let (other, new_token) = owner();
        owned.insert(2, other[&1]);
        timers().remove(&token);
        assert_eq!(
            kill_event_with(&mut owned, 1, |_| panic!("stale native id")),
            0
        );
        assert_eq!(owned.len(), 1);
        assert!(timers().contains_key(&new_token));
        assert_eq!(
            kill_event_with(&mut owned, 2, |native| {
                assert_eq!(native, 42);
                0
            }),
            0
        );
        assert!(owned.is_empty());
    }

    #[test]
    fn one_shot_completion_during_cancel_retires_the_owner() {
        let (mut owned, token) = owner();
        assert_eq!(
            kill_event_with(&mut owned, 1, |_| {
                timers().remove(&token);
                11
            }),
            0
        );
        assert!(owned.is_empty());
    }
}
