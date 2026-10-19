//! Video-overlay MCI FREEZE/UNFREEZE records.

use runtime::Win16HostMciParameters as Parameters;
use windows_sys::Win32::Media::Multimedia::MCI_OVLY_RECT_PARMS;

use super::{MciNativeContext, call_native};

const MCIERR_UNSUPPORTED_FUNCTION: u32 = 274;
const MCI_FREEZE: u16 = 0x0844;
const MCI_UNFREEZE: u16 = 0x0845;
const MCI_OVLY_RECT: u32 = 0x0001_0000;
const MCI_OVERLAY_DEVICE_TYPE: u32 = 515;

pub(super) fn send(
    context: &MciNativeContext,
    native_id: u32,
    message: u16,
    flags: u32,
    callback: usize,
    parameters: Parameters,
) -> u32 {
    if context.state.device_type(native_id) != Some(MCI_OVERLAY_DEVICE_TYPE) {
        return MCIERR_UNSUPPORTED_FUNCTION;
    }

    match (message, flags & MCI_OVLY_RECT != 0, parameters) {
        (MCI_FREEZE, false, Parameters::Generic) => {
            // With no RECT flag the overlay freezes the entire frame; the
            // native device still receives its documented overlay record.
            let mut record = MCI_OVLY_RECT_PARMS {
                dwCallback: callback,
                rc: windows_sys::Win32::Foundation::RECT {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                },
            };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            unsafe { call_native(native_id, message, flags, &mut record) }
        }
        (
            MCI_FREEZE | MCI_UNFREEZE,
            true,
            Parameters::Rectangle {
                rectangle,
                output: false,
            },
        ) => {
            let [left, top, right, bottom] = rectangle;
            let mut record = MCI_OVLY_RECT_PARMS {
                dwCallback: callback,
                rc: windows_sys::Win32::Foundation::RECT {
                    left: i32::from(left),
                    top: i32::from(top),
                    right: i32::from(right),
                    bottom: i32::from(bottom),
                },
            };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            unsafe { call_native(native_id, message, flags, &mut record) }
        }
        _ => MCIERR_UNSUPPORTED_FUNCTION,
    }
}
