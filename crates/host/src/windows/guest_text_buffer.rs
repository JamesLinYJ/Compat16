//! Owned UTF-16 scratch buffers for synchronous native text calls.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

std::thread_local! {
    // Two retained allocations also cover string comparisons. A nested call
    // takes another allocation; it never borrows an active native call's text.
    static WIDE_BUFFERS: RefCell<[Vec<u16>; 2]> = const {
        RefCell::new([Vec::new(), Vec::new()])
    };
}

/// Owns its allocation until the native operation and any callbacks return.
/// No pool borrow crosses a Windows call, and the guard stays on its thread.
pub(in crate::windows) struct GuestTextBuffer {
    wide: Vec<u16>,
    _thread: PhantomData<Rc<()>>,
}

impl GuestTextBuffer {
    pub(in crate::windows) fn acquire() -> Self {
        let wide = WIDE_BUFFERS.try_with(|buffers| {
            let Ok(mut buffers) = buffers.try_borrow_mut() else {
                return Vec::new();
            };
            let index = usize::from(buffers[1].capacity() > buffers[0].capacity());
            std::mem::take(&mut buffers[index])
        }).unwrap_or_default();
        Self { wide, _thread: PhantomData }
    }
}

impl Deref for GuestTextBuffer {
    type Target = Vec<u16>;

    fn deref(&self) -> &Self::Target { &self.wide }
}

impl DerefMut for GuestTextBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.wide }
}

impl Drop for GuestTextBuffer {
    fn drop(&mut self) {
        self.wide.clear();
        let _ = WIDE_BUFFERS.try_with(|buffers| {
            let Ok(mut buffers) = buffers.try_borrow_mut() else { return; };
            let index = usize::from(buffers[1].capacity() < buffers[0].capacity());
            if self.wide.capacity() > buffers[index].capacity() {
                std::mem::swap(&mut self.wide, &mut buffers[index]);
            }
        });
    }
}
