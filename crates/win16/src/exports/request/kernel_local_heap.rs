//! Owned request values for this Win16 API family.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelLocalHeapRequest {
    /// Initialize a local heap inside the caller-supplied Win16 selector.
    /// Offsets remain WORDs; the runtime supplies the active DS and validates
    /// the local-heap range without converting it to a host pointer here.
    LocalInit {
        selector: u16,
        start: u16,
        end: u16,
    },

    /// Allocate from the calling data segment's local heap.
    LocalAlloc {
        flags: u16,
        size: u16,
    },

    /// Resize a block in the calling data segment's local heap.
    LocalReAlloc {
        handle: u16,
        size: u16,
        flags: u16,
    },

    LocalFree {
        handle: u16,
    },

    /// Lock a local block. Win16 callers consume the returned near offset;
    /// the runtime's wide return gate additionally supplies the guest DS.
    LocalLock {
        handle: u16,
    },

    LocalUnlock {
        handle: u16,
    },

    LocalSize {
        handle: u16,
    },

    /// Resolve a near offset in the active DS local heap to its local handle.
    /// The runtime supplies DS; `offset` is not converted to a host pointer.
    LocalHandle {
        offset: u16,
    },

    LocalFlags {
        handle: u16,
    },

    LocalCompact {
        minimum: u16,
    },

    /// Query (zero) or replace the calling data segment's handle-table delta.
    /// Returns the current or newly stored WORD, not the previous value.
    LocalHandleDelta {
        delta: u16,
    },

    LocalCountFree,

    LocalHeapSize,
}
