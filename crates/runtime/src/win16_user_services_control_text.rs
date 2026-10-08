//! GetDlgItemText result validation and guest-buffer copyback.

use guest_core::memory::Memory;

use crate::{DiagnosticKind as Kind, RuntimeError};
use super::{super::guest_ranges::{GuestOutputRange, commit_guest_output}, Win16State};

pub(super) fn finish(
    state: &Win16State,
    memory: &mut Memory,
    output: Option<(GuestOutputRange, u16)>,
    value: u32,
    bytes: Vec<u8>,
) -> Result<u32, RuntimeError> {
    let Some((range, capacity)) = output else {
        if !bytes.is_empty() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GetDlgItemText returned bytes without output capacity"));
        }
        return Ok(value);
    };

    if value == u32::MAX {
        if !bytes.is_empty() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GetDlgItemText sentinel result contains output bytes"));
        }
    } else if !bytes.is_empty() {
        let count = value as usize;
        if count >= usize::from(capacity) || bytes.len() != count + 1
            || bytes[count] != 0 || bytes[..count].contains(&0)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GetDlgItemText count does not match its terminated prefix"));
        }
        commit_guest_output(state, memory, &range, &bytes)?;
    } else if value != 0 {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "Win16 GetDlgItemText count has no returned output prefix"));
    }
    Ok(value)
}
