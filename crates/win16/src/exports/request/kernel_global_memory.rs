//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelGlobalMemoryRequest {
    GlobalAlloc {
        flags: u16,
        size: u32,
    },

    GlobalFree {
        handle: u16,
    },

    GlobalLock {
        handle: u16,
    },

    GlobalUnlock {
        handle: u16,
    },

    GlobalSize {
        handle: u16,
    },

    /// Resolve a guest segment selector to its global-memory handle and
    /// selector pair. The selector is a guest value, never a host pointer.
    GlobalHandle {
        selector: u16,
    },
}
