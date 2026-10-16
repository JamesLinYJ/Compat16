//! Checked COMPOBJ.18 GUID comparison inputs.
//!
//! The Win16 spec declares two Pascal FAR pointers and a 16-bit Boolean.
//! GUID equality compares all sixteen bytes of the fixed Windows GUID layout;
//! no COM initialization, interface reference, or host call is involved.

use guest_core::GuestMemory;
use crate::{SelectorTable, Win16Argument, Win16Error};
use super::super::request::{Win16ApiRequest, Win16LibraryRequest};
use super::call_helpers::dword_argument;

pub(super) fn decode(
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let read_guid = |far| {
        let pointer = selectors.pointer_from_far(far)?;
        let mut bytes = [0; 16];
        selectors.read(memory, pointer, &mut bytes)?;
        Ok::<_, Win16Error>(bytes)
    };
    Ok(Win16ApiRequest::Libraries(Win16LibraryRequest::IsEqualGuid {
        left: read_guid(dword_argument(arguments, 0)?)?,
        right: read_guid(dword_argument(arguments, 1)?)?,
    }))
}
