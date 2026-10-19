//! Native timer identities and guest WM_TIMER provenance.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, PostThreadMessageW, WM_TIMER};

use super::{NativeTimerRecord, Win16GuestTimerPost, WorkerState};

/// Native UINT_PTR bit that keeps an HWND-owned SetSystemTimer from replacing
/// a SetTimer that uses the same guest id. The bit is not guest-visible.
pub(in crate::windows::win16_windows) const SYSTEM_TIMER_NATIVE_ID_BIT: usize = 0x1_0000;

fn reserves_system_timer_native_id(candidate: usize) -> bool {
    (SYSTEM_TIMER_NATIVE_ID_BIT..=SYSTEM_TIMER_NATIVE_ID_BIT | usize::from(u16::MAX))
        .contains(&candidate)
}

pub(in crate::windows::win16_windows) fn allocate_host_timer_id(
    state: &Rc<RefCell<WorkerState>>,
) -> Option<u64> {
    let mut state = state.borrow_mut();
    let id = state.next_host_timer_id;
    state.next_host_timer_id = id.checked_add(1)?;
    Some(id)
}

pub(in crate::windows::win16_windows) fn allocate_native_callback_timer_id(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Option<usize> {
    let mut state = state.borrow_mut();
    loop {
        let candidate = state.next_native_callback_timer_id;
        if candidate <= u16::MAX as usize || reserves_system_timer_native_id(candidate) {
            state.next_native_callback_timer_id = u16::MAX as usize;
            return None;
        }
        state.next_native_callback_timer_id = candidate - 1;
        let key = (hwnd as usize, candidate);
        if !state.timer_by_native.contains_key(&key)
            && !state.native_timers.contains(&key)
            && !state.guest_timer_posts.contains_key(&key)
        {
            return Some(candidate);
        }
    }
}

pub(in crate::windows::win16_windows) fn register_native_timer(
    state: &Rc<RefCell<WorkerState>>,
    record: NativeTimerRecord,
    allow_same_id_replacement: bool,
) -> bool {
    let mut state = state.borrow_mut();
    let key = (record.hwnd, record.native_id);
    if state.guest_timer_posts.contains_key(&key) {
        return false;
    }
    if let Some(previous_id) = state.timer_by_native.get(&key).copied() {
        if !allow_same_id_replacement {
            return false;
        }
        let Some(previous) = state.timer_records.get(&previous_id).copied() else {
            return false;
        };
        let same_guest_timer = previous.window == record.window
            && previous.guest_timer_id == record.guest_timer_id
            && previous.system == record.system;
        // USER may recycle an HWND after its previous window has been
        // destroyed. A callback-free timer has no guest FAR provenance to
        // preserve, and the OS has already retired that window's timer; allow
        // the new window incarnation to claim the same native (HWND, ID).
        let recycled_window =
            !previous.active && previous.window != record.window && !previous.guest_callback;
        if previous.guest_callback || (!same_guest_timer && !recycled_window) {
            return false;
        }
        if let Some(previous) = state.timer_records.get_mut(&previous_id) {
            previous.active = false;
        }
    }
    state.timer_records.insert(record.host_id, record);
    state.timer_by_native.insert(key, record.host_id);
    state.native_timers.insert(key);
    true
}

pub(in crate::windows::win16_windows) fn native_timer_record(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    native_id: usize,
) -> Option<NativeTimerRecord> {
    let state = state.borrow();
    let host_id = state.timer_by_native.get(&(hwnd as usize, native_id))?;
    state.timer_records.get(host_id).copied()
}

pub(in crate::windows::win16_windows) fn timer_record_by_host_id(
    state: &Rc<RefCell<WorkerState>>,
    host_id: u64,
) -> Option<NativeTimerRecord> {
    state.borrow().timer_records.get(&host_id).copied()
}

pub(in crate::windows::win16_windows) fn retire_native_timer(
    state: &Rc<RefCell<WorkerState>>,
    host_id: u64,
) -> Option<NativeTimerRecord> {
    let mut state = state.borrow_mut();
    let record = state.timer_records.get_mut(&host_id)?;
    record.active = false;
    let record = *record;
    let key = (record.hwnd, record.native_id);
    if state.timer_by_native.get(&key) == Some(&host_id) {
        state.native_timers.remove(&key);
    }
    Some(record)
}

pub(in crate::windows::win16_windows) fn host_timer_proc_pointer() -> isize {
    super::super::win16_window_callbacks::host_timer_proc as *const () as isize
}

pub(in crate::windows::win16_windows) fn post_guest_timer_message(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    guest_message: u16,
    guest_w_param: u16,
    guest_l_param: u32,
) -> Result<bool, RuntimeError> {
    if !runtime::Win16ScalarMessage::is_timer_message(guest_message) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "a non-timer message requested a guest timer-post sidecar",
        ));
    }
    let key = {
        let mut state = state.borrow_mut();
        let owner = hwnd as usize;
        let token = loop {
            let candidate = state.next_guest_timer_post_token;
            if candidate <= u16::MAX as usize || reserves_system_timer_native_id(candidate) {
                state.next_guest_timer_post_token = u16::MAX as usize;
                return Err(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 guest timer-post sidecar identities are exhausted",
                ));
            }
            state.next_guest_timer_post_token = candidate - 1;
            let key = (owner, candidate);
            if !state.native_timers.contains(&key)
                && !state.timer_by_native.contains_key(&key)
                && !state.guest_timer_posts.contains_key(&key)
            {
                break candidate;
            }
        };
        let key = (owner, token);
        state.guest_timer_posts.insert(
            key,
            Win16GuestTimerPost {
                guest_message,
                guest_w_param,
                guest_l_param,
            },
        );
        key
    };
    let posted = if hwnd.is_null() {
        let thread = crate::windows::win32_safe::current_thread_id();
        // SAFETY: PostThreadMessageW queues scalar parameters to a thread id.
        unsafe { PostThreadMessageW(thread, WM_TIMER, key.1, host_timer_proc_pointer()) }
    } else {
        // SAFETY: PostMessageW queues scalar message parameters. Any pointer in lParam stays valid until the receiving window procedure returns.
        unsafe { PostMessageW(hwnd, WM_TIMER, key.1, host_timer_proc_pointer()) }
    };
    if posted == 0 {
        state.borrow_mut().guest_timer_posts.remove(&key);
        return Ok(false);
    }
    Ok(true)
}

pub(in crate::windows::win16_windows) fn guest_timer_post(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    marker_w_param: usize,
    remove: bool,
) -> Option<Win16GuestTimerPost> {
    let mut state = state.borrow_mut();
    let key = (hwnd as usize, marker_w_param);
    if remove {
        state.guest_timer_posts.remove(&key)
    } else {
        state.guest_timer_posts.get(&key).copied()
    }
}
