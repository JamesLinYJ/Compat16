//! Owned MCI_OPEN argument projection and checked Win16 RECT narrowing.

use std::ptr;

use runtime::{RuntimeError, Win16HostMciValue as Value};

use super::wide_terminated;
use crate::windows::guest_text::GuestTextCodec;

#[derive(Debug)]
pub(super) struct MciOpenRegistrationFailure {
    pub(super) primary: RuntimeError,
    pub(super) close_result: u32,
}

impl std::fmt::Display for MciOpenRegistrationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; rollback MCI_CLOSE returned 0x{:08X}",
            self.primary, self.close_result
        )
    }
}

impl std::error::Error for MciOpenRegistrationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

pub(super) enum OpenArgument {
    None,
    Text(Vec<u16>),
    ResourceId(u32),
}

impl OpenArgument {
    pub(super) fn as_ptr(&self) -> *const u16 {
        match self {
            Self::None => ptr::null(),
            Self::Text(value) => value.as_ptr(),
            // SDK MCI_OPEN TYPE_ID/ELEMENT_ID encode numeric values in the
            // string-pointer slot; preserve the entire Win16 DWORD bit pattern.
            Self::ResourceId(value) => *value as usize as *const u16,
        }
    }

    pub(super) fn resource_id(&self) -> Option<u32> {
        match self {
            Self::ResourceId(value) => Some(*value),
            _ => None,
        }
    }
}

pub(super) enum OpenArgumentError {
    Runtime(RuntimeError),
}

pub(super) fn open_argument(
    value: Option<&Value>,
    codec: GuestTextCodec,
) -> Result<OpenArgument, OpenArgumentError> {
    match value {
        None => Ok(OpenArgument::None),
        Some(Value::Ansi(value)) => wide_terminated(codec, value)
            .map(OpenArgument::Text)
            .map_err(OpenArgumentError::Runtime),
        Some(Value::ResourceId(value) | Value::ElementId(value)) => {
            Ok(OpenArgument::ResourceId(*value))
        }
    }
}

pub(super) fn open_device_type(value: Option<&Value>) -> Option<u32> {
    match value {
        // The device-type ordinal itself is the low WORD, while `open_argument`
        // separately retains the full encoded DWORD for the official call.
        Some(Value::ResourceId(value)) => Some(*value & 0xffff),
        Some(Value::Ansi(name)) if name.eq_ignore_ascii_case(b"waveaudio") => Some(522),
        Some(Value::Ansi(name)) if name.eq_ignore_ascii_case(b"animation") => Some(519),
        Some(Value::Ansi(name)) if name.eq_ignore_ascii_case(b"overlay") => Some(515),
        _ => None,
    }
}

pub(super) fn rect16(rect: windows_sys::Win32::Foundation::RECT) -> Option<[i16; 4]> {
    Some([
        i16::try_from(rect.left).ok()?,
        i16::try_from(rect.top).ok()?,
        i16::try_from(rect.right).ok()?,
        i16::try_from(rect.bottom).ok()?,
    ])
}
