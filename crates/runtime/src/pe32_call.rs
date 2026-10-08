//! Checked guest-x86 call frames for PE32 code executed by the portable CPU.
//!
//! This boundary never converts a PE32 target to a host function pointer. It
//! prepares guest RAM and registers for the x86 interpreter, then recognizes a
//! reserved checked continuation gate at an instruction boundary.

mod environment;
mod frame;
mod thunk;

pub(crate) use environment::{
    Pe32GuestCodeRange, Pe32GuestExecutionEnvironment, Pe32GuestStackRange, Pe32SegmentAccess,
    Pe32SegmentMapping,
};
pub(crate) use frame::{
    Pe32CallConvention, Pe32CallNonce, Pe32ExecutingCall, Pe32ReturnObservation,
    begin_pe32_call,
};
pub(crate) use thunk::{
    Pe32GenericThunkTarget, process_attach_arguments, process_detach_arguments,
    validate_generic_thunk_target,
};
