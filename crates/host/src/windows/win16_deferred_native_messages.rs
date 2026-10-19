//! Native messages removed by a reentrant STA pump and returned to USER later.
//!
//! The queue owns the complete native MSG so HWND, message parameters, time,
//! and screen point survive nested COM pumping. Reservations are counted
//! across reentrant PeekMessage calls so every PM_REMOVE has queue capacity
//! reserved before it can consume a native message.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{MSG, WM_QUIT};

use super::win16_window_worker::WorkerState;

#[derive(Default)]
pub(in crate::windows::win16_windows) struct DeferredNativeMessageQueue {
    messages: VecDeque<DeferredNativeMessage>,
    outstanding_reservations: usize,
}

#[derive(Clone, Copy)]
struct DeferredNativeMessage {
    native: MSG,
    // Exact guest cookie for retirement; the FIFO never owns an HDROP lease.
    guest_window: Option<runtime::Win16HostWindow>,
    observed_by_guest_queue_check: bool,
}

impl DeferredNativeMessageQueue {
    fn reserve_slot(&mut self) -> Result<(), RuntimeError> {
        let reservations = self
            .outstanding_reservations
            .checked_add(1)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "deferred USER message reservation count overflowed",
                )
            })?;
        self.messages.try_reserve(reservations).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve storage before removing a native USER message",
                error,
            )
        })?;
        self.outstanding_reservations = reservations;
        Ok(())
    }

    fn store_reserved(
        &mut self,
        message: MSG,
        guest_window: Option<runtime::Win16HostWindow>,
    ) -> Result<(), RuntimeError> {
        if self.outstanding_reservations == 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "deferred USER message has no pre-removal capacity reservation",
            ));
        }
        self.messages.push_back(DeferredNativeMessage {
            native: message,
            guest_window,
            // Native PM_REMOVE does not count as the guest runtime observing
            // this virtual queue entry.
            observed_by_guest_queue_check: false,
        });
        self.outstanding_reservations -= 1;
        Ok(())
    }

    fn cancel_reservation(&mut self) {
        self.outstanding_reservations = self.outstanding_reservations.saturating_sub(1);
    }

    pub(super) fn retire_window(&mut self, window: runtime::Win16HostWindow) {
        self.messages
            .retain(|message| message.guest_window != Some(window));
    }
}

pub(super) struct DeferredNativeMessageReservation {
    state: Rc<RefCell<WorkerState>>,
    active: bool,
}

pub(super) fn reserve_slot(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<DeferredNativeMessageReservation, RuntimeError> {
    {
        let mut state = state.try_borrow_mut().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "reserve deferred USER message storage without a conflicting state borrow",
            )
        })?;
        state.deferred_native_messages.reserve_slot()?;
    }
    Ok(DeferredNativeMessageReservation {
        state: Rc::clone(state),
        active: true,
    })
}

impl DeferredNativeMessageReservation {
    pub(super) fn defer(
        mut self,
        message: MSG,
        guest_window: Option<runtime::Win16HostWindow>,
    ) -> Result<(), RuntimeError> {
        {
            let mut state = self.state.try_borrow_mut().map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "retain a removed USER message without a conflicting state borrow",
                )
            })?;
            state
                .deferred_native_messages
                .store_reserved(message, guest_window)?;
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for DeferredNativeMessageReservation {
    fn drop(&mut self) {
        if self.active {
            if let Ok(mut state) = self.state.try_borrow_mut() {
                state.deferred_native_messages.cancel_reservation();
            }
        }
    }
}

pub(super) fn peek_matching(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    min_message: u32,
    max_message: u32,
    remove: bool,
) -> Result<Option<MSG>, RuntimeError> {
    let mut state = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "read deferred USER messages without a conflicting worker-state borrow",
        )
    })?;
    let messages = &mut state.deferred_native_messages.messages;
    let Some(index) = messages
        .iter()
        .position(|message| matches_filter(&message.native, hwnd, min_message, max_message))
    else {
        return Ok(None);
    };
    Ok(if remove {
        messages.remove(index).map(|message| message.native)
    } else {
        messages.get_mut(index).map(|message| {
            message.observed_by_guest_queue_check = true;
            message.native
        })
    })
}

pub(super) fn remove_exact(
    state: &Rc<RefCell<WorkerState>>,
    expected: &MSG,
    hwnd: HWND,
    min_message: u32,
    max_message: u32,
) -> Result<Option<MSG>, RuntimeError> {
    let mut state = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "remove a deferred USER message without a conflicting worker-state borrow",
        )
    })?;
    let messages = &mut state.deferred_native_messages.messages;
    let Some(index) = messages.iter().position(|message| {
        same_message(&message.native, expected)
            && matches_filter(&message.native, hwnd, min_message, max_message)
    }) else {
        return Ok(None);
    };
    Ok(messages.remove(index).map(|message| message.native))
}

pub(super) fn observe_new_matching(
    state: &Rc<RefCell<WorkerState>>,
    filter: Option<(HWND, u32, u32)>,
) -> Result<bool, RuntimeError> {
    let mut state = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "observe deferred USER input without a conflicting worker-state borrow",
        )
    })?;
    let messages = &mut state.deferred_native_messages.messages;
    let is_matching = |message: &DeferredNativeMessage| {
        filter.is_none_or(|(hwnd, min, max)| matches_filter(&message.native, hwnd, min, max))
    };
    let found = messages
        .iter()
        .any(|message| !message.observed_by_guest_queue_check && is_matching(message));
    for message in messages.iter_mut() {
        if is_matching(message) {
            message.observed_by_guest_queue_check = true;
        }
    }
    Ok(found)
}

fn matches_filter(message: &MSG, hwnd: HWND, min_message: u32, max_message: u32) -> bool {
    let window_matches = if hwnd.is_null() {
        true
    } else if hwnd as isize == -1 {
        message.hwnd.is_null()
    } else if message.hwnd.is_null() {
        false
    } else {
        message.hwnd == hwnd || { crate::windows::win32_safe::is_child(hwnd, message.hwnd) != 0 }
    };
    let id_matches = message.message == WM_QUIT
        || (min_message == 0 && max_message == 0)
        || (min_message <= max_message && (min_message..=max_message).contains(&message.message));
    window_matches && id_matches
}

fn same_message(left: &MSG, right: &MSG) -> bool {
    left.hwnd == right.hwnd
        && left.message == right.message
        && left.wParam == right.wParam
        && left.lParam == right.lParam
        && left.time == right.time
        && left.pt.x == right.pt.x
        && left.pt.y == right.pt.y
}
