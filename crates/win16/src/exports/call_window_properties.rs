//! USER window-property export decoder.

use super::{Win16ApiRequest, Win16ExportId};
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    id: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    super::super::request::window_properties::decode_window_properties(
        id.ordinal(), arguments, selectors, memory,
    )
    .map(Win16ApiRequest::WindowProperties)
}
