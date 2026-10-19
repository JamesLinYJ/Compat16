//! Synchronous guest control messages, carried without native guest pointers.

use super::win16_window_worker::WorkerState;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMessage, Win16HostMessageOutput,
    Win16HostMessageResult, Win16HostWindow,
};
use std::{cell::RefCell, rc::Rc};
use windows_sys::Win32::{
    Foundation::HWND,
    UI::WindowsAndMessaging::{SendMessageW, WM_NULL},
};

const TAG: usize = 0x5749_4e31_3653_454e;
#[derive(Clone, Copy)]
struct Carrier {
    id: usize,
    operation: u64,
    window: Win16HostWindow,
    hwnd: usize,
    message: u16,
    w_param: u16,
    l_param: u32,
    delivered: bool,
}
#[derive(Default)]
struct Carriers {
    next: usize,
    frames: Vec<Carrier>,
}
thread_local! { static CARRIERS: RefCell<Carriers> = RefCell::new(Carriers::default()); }
struct Guard(usize);
impl Drop for Guard {
    fn drop(&mut self) {
        CARRIERS.with(|slot| {
            let mut stack = slot.borrow_mut();
            if let Some(index) = stack.frames.iter().rposition(|frame| frame.id == self.0) {
                stack.frames.remove(index);
            }
        });
    }
}

pub(super) fn send(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    message: u16,
    w_param: u16,
    l_param: u32,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    let Some(hwnd) = super::win16_window_identity::resolve(state, window) else {
        return Ok(None);
    };
    if message < 0x0400 || !super::win16_native_procedures::is_subclassed(state, window) {
        return Ok(None);
    }
    let operation = state
        .borrow()
        .active_operations
        .last()
        .map(|active| active.id)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "subclass send has no exact worker operation",
            )
        })?;
    let id = CARRIERS.with(|slot| -> Result<usize, RuntimeError> {
        let mut stack = slot.borrow_mut();
        let id = stack
            .next
            .checked_add(1)
            .filter(|id| *id <= isize::MAX as usize)
            .ok_or_else(|| {
                RuntimeError::new(Kind::ResourceExhausted, "subclass send identity exhausted")
            })?;
        stack.frames.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain synchronous subclass message",
                error,
            )
        })?;
        stack.next = id;
        stack.frames.push(Carrier {
            id,
            operation,
            window,
            hwnd: hwnd as usize,
            message,
            w_param,
            l_param,
            delivered: false,
        });
        Ok(id)
    })?;
    let _guard = Guard(id);
    // USER sees only the private numeric tag and nonce. Original Win16 words
    // stay in this owned thread-local frame across nested guest callbacks.
    // SAFETY: SendMessageW runs synchronously on the window thread. Pointer arguments are caller-owned records that stay live for the call and are not guest addresses.
    let value = unsafe { SendMessageW(hwnd, WM_NULL, TAG, id as isize) } as u32;
    Ok(Some(Win16HostMessageResult {
        value,
        output: Win16HostMessageOutput::None,
        dialog_result: None,
    }))
}

pub(super) fn capture(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> Option<(u16, Win16HostMessage)> {
    if message != WM_NULL || w_param != TAG || l_param <= 0 {
        return None;
    }
    let operation = state.borrow().active_operations.last()?.id;
    CARRIERS.with(|slot| {
        let mut stack = slot.borrow_mut();
        let frame = stack.frames.last_mut()?;
        if frame.delivered
            || !(frame.id == l_param as usize
                && frame.operation == operation
                && frame.window == window
                && frame.hwnd == hwnd as usize)
        {
            return None;
        }
        // Consume ingress before entering guest code. A nested or foreign
        // message with guessed marker bits cannot replay the live payload.
        frame.delivered = true;
        Some((
            frame.message,
            Win16HostMessage::GuestOpaque {
                message: frame.message,
                w_param: frame.w_param,
                l_param: frame.l_param,
            },
        ))
    })
}
