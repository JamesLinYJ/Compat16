//! Dispatch already checked Win16 argument frames to API-family decoders.

use super::*;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match super::call_request_routes::route(descriptor.id) {
        super::call_request_routes::DecodeRoute::Kernel =>
            super::call_requests_kernel::decode(descriptor, arguments, selectors, memory)?,
        super::call_request_routes::DecodeRoute::User =>
            super::call_requests_user::decode(descriptor, arguments, selectors, memory)?,
        super::call_request_routes::DecodeRoute::Gdi =>
            super::call_requests_gdi::decode(descriptor, arguments, selectors, memory)?,
        super::call_request_routes::DecodeRoute::Libraries =>
            super::call_requests_libraries::decode(descriptor, arguments, selectors, memory)?,
    };
    request.ok_or(Win16Error::InvalidRange)
}
