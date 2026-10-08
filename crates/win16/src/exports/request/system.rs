//! Typed requests for SYSTEM.DRV APIs backed by the runtime host boundary.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16SystemRequest {
    GetSystemMSecCount,
}

/// Decode the small SYSTEM.DRV subset with a complete runtime contract.
/// Timer registration, FPU save-state, A20, and legacy inquiry exports are
/// intentionally left unclaimed until their guest-owned state is modeled.
pub fn decode_system(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16SystemRequest>, Win16Error> {
    match ordinal {
        6 if arguments.is_empty() => Ok(Some(Win16SystemRequest::GetSystemMSecCount)),
        6 => Err(Win16Error::InvalidRange),
        _ => Ok(None),
    }
}
