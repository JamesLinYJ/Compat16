//! MCI SAVE/LOAD parameter records, including the video-overlay RECT tail.

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Media::Multimedia::{
    MCI_LOAD_PARMSW, MCI_OVLY_LOAD_PARMSW, MCI_OVLY_SAVE_PARMSW, MCI_SAVE_PARMSW,
};

use super::{MciNativeContext, wide_terminated};
use crate::windows::guest_text::GuestTextCodec;

const MCI_SAVE: u16 = 0x0813;
const MCI_OVERLAY_DEVICE_TYPE: u32 = 515;
const MCIERR_UNSUPPORTED_FUNCTION: u32 = 274;

pub(super) fn send(
    context: &MciNativeContext,
    native_id: u32,
    message: u16,
    flags: u32,
    callback: usize,
    filename: Vec<u8>,
    rectangle: Option<[i16; 4]>,
    codec: GuestTextCodec,
) -> Result<u32, RuntimeError> {
    let filename = wide_terminated(codec, &filename)?;
    let is_overlay = context.state.device_type(native_id) == Some(MCI_OVERLAY_DEVICE_TYPE);
    match (is_overlay, rectangle) {
        (true, Some([left, top, right, bottom])) => {
            let rc = windows_sys::Win32::Foundation::RECT {
                left: i32::from(left),
                top: i32::from(top),
                right: i32::from(right),
                bottom: i32::from(bottom),
            };
            if message == MCI_SAVE {
                let mut record = MCI_OVLY_SAVE_PARMSW {
                    dwCallback: callback,
                    lpfilename: filename.as_ptr(),
                    rc,
                };
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                Ok(unsafe { super::call_native(native_id, message, flags, &mut record) })
            } else {
                let mut record = MCI_OVLY_LOAD_PARMSW {
                    dwCallback: callback,
                    lpfilename: filename.as_ptr(),
                    rc,
                };
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                Ok(unsafe { super::call_native(native_id, message, flags, &mut record) })
            }
        }
        (true, None) => Ok(MCIERR_UNSUPPORTED_FUNCTION),
        (false, Some(_)) => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "non-overlay MCI SAVE/LOAD received an overlay RECT projection",
        )),
        (false, None) if message == MCI_SAVE => {
            let mut record = MCI_SAVE_PARMSW {
                dwCallback: callback,
                lpfilename: filename.as_ptr(),
            };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            Ok(unsafe { super::call_native(native_id, message, flags, &mut record) })
        }
        (false, None) => {
            let mut record = MCI_LOAD_PARMSW {
                dwCallback: callback,
                lpfilename: filename.as_ptr(),
            };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            Ok(unsafe { super::call_native(native_id, message, flags, &mut record) })
        }
    }
}
