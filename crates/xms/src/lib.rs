//! XMS 2.0 service over the runtime's shared guest-memory implementation.
//!
//! Handle metadata is owned here, while all guest bytes remain in the shared
//! [`guest_core::GuestMemory`] supplied by the runtime.
#![forbid(unsafe_code)]

mod dispatch;
mod model;
mod moves;
mod service;

#[cfg(test)]
mod tests;

pub use dispatch::handle_int2f;
pub use model::{
    A20State, FreeSpace, GuestFarPointer, HandleInfo, MoveRequest, PreparedCallMismatch,
    PreparedXmsCall, XmsCapabilities, XmsConfig, XmsError, XmsVersion, XMS_CAPABILITIES,
    XMS_VERSION,
};
pub use service::XmsService;
