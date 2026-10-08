//! Checked Win16 joystick structures and native joystick operations.

use super::*;
use compat_services::win16_multimedia::{
    JOYINFO16_BUTTONS_OFFSET, JOYINFO16_SIZE, JOYINFO16_X_OFFSET, JOYINFO16_Y_OFFSET,
    JOYINFO16_Z_OFFSET,
};
use guest_core::memory::Memory;
use guest_core::Registers;
use win16_abi::{Win16MultimediaCall, Win16ReturnKind};

pub(super) fn is_joystick_export(name: &str) -> bool {
    [
        "joyGetThreshold",
        "joySetThreshold",
        "joyGetPos",
        "joyReleaseCapture",
        "joySetCapture",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

impl super::super::Win16State {
    pub(super) fn multimedia_joystick_api(
        &mut self,
        call: &Win16MultimediaCall,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let name = call.name.unwrap_or("");
        if name.eq_ignore_ascii_case("joyGetThreshold") {
            let device = word(call, 0)?;
            let output = self.prepare_multimedia_output(memory, pointer(call, 1)?, 2)?
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "joystick threshold output was not prepared"))?;
            let reply = host.win16_multimedia(
                Win16HostMultimediaOperation::JoystickThresholdGet { device },
            )?;
            let Win16HostMultimediaResult::Output { result, value } = reply else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "joyGetThreshold returned the wrong multimedia result"));
            };
            if result == 0 {
                let threshold = u16::try_from(value).map_err(|_| RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native joystick threshold exceeds the Win16 WORD range",
                ))?;
                output.commit(memory, &threshold.to_le_bytes())?;
            }
            return self.finish_multimedia(registers, return_to, result, return_kind);
        }
        if name.eq_ignore_ascii_case("joyGetPos") {
            let device = word(call, 0)?;
            let output = self.prepare_multimedia_output(
                memory, pointer(call, 1)?, JOYINFO16_SIZE,
            )?.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "JOYINFO16 output was not prepared"))?;
            let reply = host.win16_multimedia(
                Win16HostMultimediaOperation::JoystickPosition { device },
            )?;
            let Win16HostMultimediaResult::JoystickPosition {
                result, x, y, z, buttons,
            } = reply else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "joyGetPos returned the wrong multimedia result"));
            };
            if result == 0 {
                let x = u16::try_from(x).map_err(|_| RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native joystick X position exceeds the Win16 WORD range",
                ))?;
                let y = u16::try_from(y).map_err(|_| RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native joystick Y position exceeds the Win16 WORD range",
                ))?;
                let z = u16::try_from(z).map_err(|_| RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native joystick Z position exceeds the Win16 WORD range",
                ))?;
                let buttons = u16::try_from(buttons).map_err(|_| RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native joystick button state exceeds the Win16 WORD range",
                ))?;
                let mut bytes = [0_u8; JOYINFO16_SIZE];
                bytes[JOYINFO16_X_OFFSET..JOYINFO16_X_OFFSET + 2]
                    .copy_from_slice(&x.to_le_bytes());
                bytes[JOYINFO16_Y_OFFSET..JOYINFO16_Y_OFFSET + 2]
                    .copy_from_slice(&y.to_le_bytes());
                bytes[JOYINFO16_Z_OFFSET..JOYINFO16_Z_OFFSET + 2]
                    .copy_from_slice(&z.to_le_bytes());
                bytes[JOYINFO16_BUTTONS_OFFSET..JOYINFO16_BUTTONS_OFFSET + 2]
                    .copy_from_slice(&buttons.to_le_bytes());
                output.commit(memory, &bytes)?;
            }
            return self.finish_multimedia(registers, return_to, result, return_kind);
        }
        if name.eq_ignore_ascii_case("joySetThreshold") {
            let result = scalar(host.win16_multimedia(
                Win16HostMultimediaOperation::JoystickThresholdSet {
                    device: word(call, 0)?,
                    threshold: word(call, 1)?,
                },
            )?)?;
            return self.finish_multimedia(registers, return_to, result, return_kind);
        }
        if name.eq_ignore_ascii_case("joyReleaseCapture") {
            let result = scalar(host.win16_multimedia(
                Win16HostMultimediaOperation::JoystickReleaseCapture {
                    device: word(call, 0)?,
                },
            )?)?;
            return self.finish_multimedia(registers, return_to, result, return_kind);
        }
        if name.eq_ignore_ascii_case("joySetCapture") {
            return Err(RuntimeError::new(Kind::CompatibilityGap,
                "joySetCapture requires Win16 joystick message translation for the guest window"));
        }
        Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 multimedia joystick dispatcher received an unsupported export"))
    }
}
