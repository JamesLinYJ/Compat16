//! Typed request for the legacy TIMER driver procedure.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16TimerDriverProcRequest {
    pub device_id: u32,
    pub driver_handle: u16,
    pub message: u16,
    pub parameter1: u32,
    pub parameter2: u32,
}

pub fn decode_timer(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16TimerDriverProcRequest>, Win16Error> {
    match (ordinal, arguments) {
        (2, [
            Win16Argument::Dword(device_id),
            Win16Argument::Word(driver_handle),
            Win16Argument::Word(message),
            Win16Argument::Dword(parameter1),
            Win16Argument::Dword(parameter2),
        ]) => Ok(Some(Win16TimerDriverProcRequest {
            device_id: *device_id,
            driver_handle: *driver_handle,
            message: *message,
            parameter1: *parameter1,
            parameter2: *parameter2,
        })),
        (2, _) => Err(Win16Error::InvalidRange),
        _ => Ok(None),
    }
}
