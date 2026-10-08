//! MCI error-string conversion with call-owned output storage.

use super::{guest_output_from_wide, wide_capacity, zeroed_wide_buffer};
use crate::windows::guest_text::GuestTextCodec;
use runtime::{RuntimeError, Win16HostMciOutput, Win16HostMciResult};
use windows_sys::Win32::Media::Multimedia::mciGetErrorStringW;

pub(super) fn get_error_string(
    error: u32,
    capacity: Option<u32>,
    codec: GuestTextCodec,
) -> Result<Win16HostMciResult, RuntimeError> {
    let mut wide = zeroed_wide_buffer(wide_capacity(capacity)?)?;
    if wide.is_empty() {
        return Ok(Win16HostMciResult {
            return_value: 0,
            output: Win16HostMciOutput::Bytes(Vec::new()),
        });
    }
    let wide_capacity = u32::try_from(wide.len()).map_err(|error| {
        RuntimeError::with_source(
            runtime::DiagnosticKind::ResourceExhausted,
            "MCI error-string capacity exceeds the Windows API width",
            error,
        )
    })?;
    let success = unsafe { mciGetErrorStringW(error, wide.as_mut_ptr(), wide_capacity) } != 0;
    let output = guest_output_from_wide(codec, &wide, capacity)?;
    Ok(Win16HostMciResult {
        return_value: u32::from(success),
        output: Win16HostMciOutput::Bytes(output),
    })
}
