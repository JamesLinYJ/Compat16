//! Legacy IME profile calls executed on the native USER owner thread.

use super::super::guest_text::GuestTextCodec;
use super::win16_window_worker::{self as worker, WorkerState};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostImeProfile, Win16HostImeProfileCall as Call,
    Win16HostImeProfileResult as Reply,
};
use std::{cell::RefCell, rc::Rc};
use windows_sys::Win32::System::WindowsProgramming::{
    IMEPROW, IMPGetIMEW, IMPQueryIMEW, IMPSetIMEW,
};

pub(super) fn execute(state: &Rc<RefCell<WorkerState>>, call: Call) -> Result<Reply, RuntimeError> {
    let is_set = matches!(&call, Call::Set { .. });
    match execute_checked(state, call) {
        // Invalid guest text or a stale window is an ordinary API failure.
        Err(error) if error.kind() == Kind::InvalidInput => Ok(if is_set {
            Reply::Status(false)
        } else {
            Reply::Profile(None)
        }),
        result => result,
    }
}

fn execute_checked(state: &Rc<RefCell<WorkerState>>, call: Call) -> Result<Reply, RuntimeError> {
    let codec = state.borrow().text_codec;
    let mut native = IMEPROW::default();
    let success = match call {
        Call::Query { name } => {
            // The query cursor is the name. Output-only fields may contain
            // uninitialized guest bytes and must not be treated as input.
            native.szName = to_fixed_wide(codec, &name)?;
            // SAFETY: native is an initialized, correctly aligned SDK record;
            // its name is an owned UTF-16 array and HWND is initialized to NULL.
            unsafe { IMPQueryIMEW(&mut native) != 0 }
        }
        Call::Get => {
            // The legacy Win16 adapter queries the default profile with NULL
            // HWND. There is no guest input profile to read or reinterpret.
            // SAFETY: native is a live initialized writable SDK structure.
            unsafe { IMPGetIMEW(std::ptr::null_mut(), &mut native) != 0 }
        }
        Call::Set { name } => {
            native.szName = to_fixed_wide(codec, &name)?;
            // Only the name selects the legacy profile. Other fields remain
            // initialized; no result profile is copied back by this operation.
            // SAFETY: native is live and holds a terminated UTF-16 name.
            return Ok(Reply::Status(unsafe {
                IMPSetIMEW(std::ptr::null_mut(), &mut native) != 0
            }));
        }
    };
    if !success {
        return Ok(Reply::Profile(None));
    }
    let window = if native.hWnd.is_null() {
        None
    } else {
        Some(worker::token_for_native(state, native.hWnd)?)
    };
    Ok(Reply::Profile(Some(Win16HostImeProfile {
        window,
        date: [
            native.InstDate.year,
            native.InstDate.month,
            native.InstDate.day,
            native.InstDate.hour,
            native.InstDate.min,
            native.InstDate.sec,
        ],
        version: native.wVersion,
        description: to_fixed_guest(codec, &native.szDescription)?,
        name: to_fixed_guest(codec, &native.szName)?,
        options: to_fixed_guest(codec, &native.szOptions)?,
    })))
}

fn to_fixed_wide<const N: usize>(
    codec: GuestTextCodec,
    bytes: &[u8; N],
) -> Result<[u16; N], RuntimeError> {
    let length = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        RuntimeError::new(
            Kind::InvalidInput,
            "legacy IME profile text is unterminated",
        )
    })?;
    let wide = codec.to_wide(&bytes[..length])?;
    if wide.len() >= N {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "legacy IME profile text exceeds its UTF-16 field",
        ));
    }
    let mut result = [0; N];
    result[..wide.len()].copy_from_slice(&wide);
    Ok(result)
}

fn to_fixed_guest<const N: usize>(
    codec: GuestTextCodec,
    wide: &[u16; N],
) -> Result<[u8; N], RuntimeError> {
    let length = wide.iter().position(|unit| *unit == 0).unwrap_or(N);
    // Fixed legacy byte capacities differ from UTF-16 capacities. Reuse the
    // shared codec's complete-character truncation instead of cutting DBCS bytes.
    let encoded = codec.from_wide_bounded(&wide[..length], N - 1)?;
    let mut result = [0; N];
    result[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    Ok(result)
}
