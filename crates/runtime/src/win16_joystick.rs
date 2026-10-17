//! Windows 3.1 joystick calls over a host that never sees guest addresses.
//!
//! `joySetCapture` forwards the guest window word and does not post `MM_JOY*`
//! messages. `joySetCalibration` has no published 3.1 prototype and no
//! calibration hardware, so it returns `JOYERR_NOCANDO` without a host call.
//! `joyGetPosEx` accepts only the `JOYINFO` axes and buttons.

use guest_core::memory::Memory;
use win16_abi::{
    JOY_RETURN_SUPPORTED, JOY_RETURNBUTTONS, JOY_RETURNX, JOY_RETURNY, JOY_RETURNZ, JOYCAPS16_SIZE,
    JOYERR_NOCANDO, JOYERR_PARMS, JOYINFO16_SIZE, JOYINFOEX16_BUTTONS_OFFSET, JOYINFOEX16_SIZE,
    JOYINFOEX16_X_OFFSET, JOYINFOEX16_Y_OFFSET, JOYINFOEX16_Z_OFFSET, Win16JoyCaps16,
    Win16JoyInfo16, Win16JoystickRequest,
};

use super::{
    Win16State,
    guest_ranges::{GuestOutputRange, commit_guest_writes},
};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostJoystickOperation as Operation,
    Win16HostJoystickResult as ResultValue,
};

impl Win16State {
    pub(in crate::win16_runtime) fn joystick_api(
        &mut self,
        request: Win16JoystickRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16JoystickRequest::GetNumDevs => {
                match host.win16_joystick(Operation::DeviceCount)? {
                    ResultValue::Count(count) => Ok(u32::from(count)),
                    _ => Err(invariant("joyGetNumDevs returned the wrong result shape")),
                }
            }
            Win16JoystickRequest::GetDevCaps { device, caps, size } => {
                self.joy_dev_caps(device, caps, size, memory, host)
            }
            Win16JoystickRequest::GetPos { device, info } => {
                self.joy_position(device, info, memory, host)
            }
            Win16JoystickRequest::GetThreshold { device, threshold } => {
                self.joy_threshold(device, threshold, memory, host)
            }
            Win16JoystickRequest::ReleaseCapture { device } => status(
                host.win16_joystick(Operation::ReleaseCapture { device })?,
                "joyReleaseCapture returned the wrong result shape",
            ),
            Win16JoystickRequest::SetCapture {
                window,
                device,
                period,
                changed,
            } => {
                if window == 0 {
                    return Ok(u32::from(JOYERR_PARMS));
                }
                status(
                    host.win16_joystick(Operation::SetCapture {
                        window,
                        device,
                        period,
                        changed: changed != 0,
                    })?,
                    "joySetCapture returned the wrong result shape",
                )
            }
            Win16JoystickRequest::SetThreshold { device, threshold } => status(
                host.win16_joystick(Operation::ThresholdSet { device, threshold })?,
                "joySetThreshold returned the wrong result shape",
            ),
            Win16JoystickRequest::SetCalibration { .. } => Ok(u32::from(JOYERR_NOCANDO)),
            Win16JoystickRequest::GetPosEx { device, info } => {
                self.joy_position_ex(device, info, memory, host)
            }
        }
    }

    fn joy_dev_caps(
        &mut self,
        device: u16,
        caps: u32,
        size: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let length = usize::from(size).min(JOYCAPS16_SIZE);
        if length == 0 {
            return Ok(0);
        }
        let output = match capture_output(self, memory, caps, length) {
            Ok(output) => output,
            Err(error) => return parameter_or(error),
        };
        let reply = host.win16_joystick(Operation::DevCaps { device })?;
        let ResultValue::Caps { result, caps } = reply else {
            return Err(invariant("joyGetDevCaps returned the wrong result shape"));
        };
        if result != 0 {
            if caps.is_some() {
                return Err(invariant("failed joyGetDevCaps returned capability bytes"));
            }
            return Ok(u32::from(result));
        }
        let caps =
            caps.ok_or_else(|| invariant("successful joyGetDevCaps omitted capabilities"))?;
        let mut bytes = Win16JoyCaps16 {
            manufacturer: caps.manufacturer,
            product: caps.product,
            name: caps.name,
            x_min: caps.x_min,
            x_max: caps.x_max,
            y_min: caps.y_min,
            y_max: caps.y_max,
            z_min: caps.z_min,
            z_max: caps.z_max,
            buttons: caps.buttons,
            period_min: caps.period_min,
            period_max: caps.period_max,
        }
        .encode()
        .to_vec();
        bytes.truncate(length);
        commit_output(self, memory, output, bytes)
    }

    fn joy_position(
        &mut self,
        device: u16,
        info: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let output = match capture_output(self, memory, info, JOYINFO16_SIZE) {
            Ok(output) => output,
            Err(error) => return parameter_or(error),
        };
        let reply = host.win16_joystick(Operation::Position { device })?;
        let ResultValue::Position {
            result,
            x,
            y,
            z,
            buttons,
        } = reply
        else {
            return Err(invariant("joyGetPos returned the wrong result shape"));
        };
        if result != 0 {
            return Ok(u32::from(result));
        }
        let bytes = Win16JoyInfo16 { x, y, z, buttons }.encode().to_vec();
        commit_output(self, memory, output, bytes)
    }

    fn joy_threshold(
        &mut self,
        device: u16,
        threshold: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let output = match capture_output(self, memory, threshold, 2) {
            Ok(output) => output,
            Err(error) => return parameter_or(error),
        };
        let reply = host.win16_joystick(Operation::ThresholdGet { device })?;
        let ResultValue::Threshold { result, value } = reply else {
            return Err(invariant("joyGetThreshold returned the wrong result shape"));
        };
        if result != 0 {
            return Ok(u32::from(result));
        }
        commit_output(self, memory, output, value.to_le_bytes().to_vec())
    }

    fn joy_position_ex(
        &mut self,
        device: u16,
        info: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let header = match read_guest(self, memory, info, 8) {
            Ok(header) => header,
            Err(error) => return parameter_or(error),
        };
        let mut size_bytes = [0; 4];
        let mut flag_bytes = [0; 4];
        size_bytes.copy_from_slice(&header[0..4]);
        flag_bytes.copy_from_slice(&header[4..8]);
        let size = u32::from_le_bytes(size_bytes);
        let flags = u32::from_le_bytes(flag_bytes);
        if size != JOYINFOEX16_SIZE as u32 {
            return Ok(u32::from(JOYERR_PARMS));
        }
        let output = match capture_output(self, memory, info, JOYINFOEX16_SIZE) {
            Ok(output) => output,
            Err(error) => return parameter_or(error),
        };
        if flags & !JOY_RETURN_SUPPORTED != 0 {
            return Ok(u32::from(JOYERR_NOCANDO));
        }
        // A zero request mask still checks that the device exists.
        // In particular, it must not report success when no driver is installed.
        let reply = host.win16_joystick(Operation::Position { device })?;
        let ResultValue::Position {
            result,
            x,
            y,
            z,
            buttons,
        } = reply
        else {
            return Err(invariant("joyGetPosEx returned the wrong result shape"));
        };
        if result != 0 {
            return Ok(u32::from(result));
        }
        let mut bytes = match read_guest(self, memory, info, JOYINFOEX16_SIZE) {
            Ok(bytes) => bytes,
            Err(error) => return parameter_or(error),
        };
        if flags & JOY_RETURNX != 0 {
            bytes[JOYINFOEX16_X_OFFSET..JOYINFOEX16_X_OFFSET + 4]
                .copy_from_slice(&u32::from(x).to_le_bytes());
        }
        if flags & JOY_RETURNY != 0 {
            bytes[JOYINFOEX16_Y_OFFSET..JOYINFOEX16_Y_OFFSET + 4]
                .copy_from_slice(&u32::from(y).to_le_bytes());
        }
        if flags & JOY_RETURNZ != 0 {
            bytes[JOYINFOEX16_Z_OFFSET..JOYINFOEX16_Z_OFFSET + 4]
                .copy_from_slice(&u32::from(z).to_le_bytes());
        }
        if flags & JOY_RETURNBUTTONS != 0 {
            bytes[JOYINFOEX16_BUTTONS_OFFSET..JOYINFOEX16_BUTTONS_OFFSET + 4]
                .copy_from_slice(&u32::from(buttons).to_le_bytes());
        }
        commit_output(self, memory, output, bytes)
    }
}

fn capture_output(
    state: &Win16State,
    memory: &Memory,
    far: u32,
    size: usize,
) -> Result<GuestOutputRange, RuntimeError> {
    let pointer = state
        .selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    GuestOutputRange::capture(state, memory, pointer, size)
}

fn read_guest(
    state: &Win16State,
    memory: &Memory,
    far: u32,
    size: usize,
) -> Result<Vec<u8>, RuntimeError> {
    let pointer = state
        .selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    let mut bytes = vec![0; size];
    state
        .selectors
        .read(memory, pointer, &mut bytes)
        .map_err(crate::runtime_error)?;
    Ok(bytes)
}

fn commit_output(
    state: &Win16State,
    memory: &mut Memory,
    output: GuestOutputRange,
    bytes: Vec<u8>,
) -> Result<u32, RuntimeError> {
    match commit_guest_writes(state, memory, vec![(output, bytes)]) {
        Ok(()) => Ok(0),
        Err(error) => parameter_or(error),
    }
}

fn status(reply: ResultValue, message: &str) -> Result<u32, RuntimeError> {
    match reply {
        ResultValue::Status(result) => Ok(u32::from(result)),
        _ => Err(invariant(message)),
    }
}

fn parameter_or(error: RuntimeError) -> Result<u32, RuntimeError> {
    if is_guest_parameter(&error) {
        Ok(u32::from(JOYERR_PARMS))
    } else {
        Err(error)
    }
}

fn is_guest_parameter(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

fn invariant(message: &str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

#[cfg(test)]
#[path = "win16_joystick_tests.rs"]
mod tests;
