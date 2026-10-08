//! Safe DPMI linear-memory services backed by the runtime's shared guest RAM.
//!
//! `DpmiMemory` owns allocation metadata only. Its configured physical arena
//! is an offset into the single `GuestMemory`; allocation, resize, and guest
//! access never create a second backing buffer. The runtime must reserve a
//! non-overlapping arena for this service and route DPMI linear accesses
//! through the allocator's checked translation and access methods.
//!
//! INT 31h support is limited to 0501h (allocate), 0502h (free), 0503h
//! (resize), and 0604h (page size). Other functions return explicit errors.

mod allocator;
mod dispatch;
mod types;

#[cfg(test)]
mod tests;

pub use allocator::DpmiMemory;
pub use types::{
    Allocation, ArenaBounds, DpmiError, DpmiHandle, DpmiMemoryStats, LinearMapping,
    ServiceDisposition, DPMI_PAGE_SIZE,
};
