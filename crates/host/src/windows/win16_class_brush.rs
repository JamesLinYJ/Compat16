//! Native class-brush retirement shared with the host GDI identity table.
//!
//! USER deletes the current background brush when UnregisterClass succeeds.
//! This acknowledgement retires that exact GDI object incarnation before its
//! host token can be used or cleaned up again. Replacing the class brush does
//! not retire the displaced brush, which is still owned by the GDI table.

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

#[derive(Clone)]
pub(in crate::windows) struct Win16ClassBrush {
    pub(super) handle: usize,
    pub(super) retired: Arc<AtomicBool>,
}

impl Win16ClassBrush {
    pub(in crate::windows) fn retire(&self) {
        // Stock/system brushes survive native class unregistration. Keep
        // their existing aliases usable; only acknowledge an actual deletion.
        // SAFETY: This is the host-private brush incarnation installed on the
        // class whose successful UnregisterClass acknowledgement we received.
        if unsafe { windows_sys::Win32::Graphics::Gdi::GetObjectType(self.handle as _) } == 0 {
            self.retired.store(true, Ordering::Release);
        }
    }
}

/// System-color and cleared backgrounds have no guest GDI owner to retire.
#[derive(Clone, Default)]
pub(in crate::windows) struct NativeClassBackground {
    pub(in crate::windows) handle: usize,
    pub(in crate::windows) brush: Option<Win16ClassBrush>,
}

impl NativeClassBackground {
    pub(in crate::windows) fn shared(handle: usize) -> Self {
        Self { handle, brush: None }
    }
}
