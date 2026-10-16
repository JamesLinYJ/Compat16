//! Checked Win16 USER update-region calls through the window callback worker.
//!
//! Guest FAR pointers and handles are resolved before the operation crosses
//! the host boundary. The continuation retains only checked guest output
//! pointers and the guest ABI result shape; native identities remain opaque.
//!
//! ScrollDC preserves the native DC mapping and uses the existing update RECT
//! coordinate saturation on return. Original Win16 behavior for coordinates
//! outside the signed 16-bit range is unverified; saturation is a bounded
//! bridge policy, not a claim of matching Win16 overflow behavior.

use guest_core::memory::Memory;
use win16_abi::{Access, Rect16, Win16ReturnKind, exports::Win16UserUpdateRequest};

use super::{Win16State, windows::WindowReturn};
use super::guest_ranges::GuestOutputRange;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostGdiObject,
    Win16HostRect, Win16HostUpdateOperation, Win16HostWindow,
    Win16WindowOperation,
};

#[derive(Clone, Copy)]
pub(in crate::win16_runtime) enum UpdateResultKind {
    Void,
    Word,
    Rect,
}

/// Continuation held while an update-region call runs on the owning window
/// worker and any synchronous guest callbacks return.
pub(super) struct Win16UpdateContinuation {
    pub(in crate::win16_runtime) result_kind: UpdateResultKind,
    pub(in crate::win16_runtime) return_kind: Win16ReturnKind,
    pub(in crate::win16_runtime) rect_output: Option<GuestOutputRange>,
}

impl Win16State {
    pub(super) fn begin_user_update_request(
        &mut self,
        request: Win16UserUpdateRequest,
        registers: &mut guest_core::Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
        descriptor_return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        let (result_kind, return_kind) = result_shape(request);
        if descriptor_return_kind != return_kind {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 USER update export has an unexpected ABI return kind"));
        }

        let mut rect_output = None;
        let operation = match request {
            Win16UserUpdateRequest::UpdateWindow { window } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                Win16HostUpdateOperation::UpdateWindow { window }
            }
            Win16UserUpdateRequest::InvalidateRect { window, rect, erase } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let rect = self.read_optional_rect(rect, memory)?;
                Win16HostUpdateOperation::InvalidateRect {
                    window, rect, erase: erase != 0,
                }
            }
            Win16UserUpdateRequest::InvalidateRgn { window, region, erase } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let Some(region) = self.mapped_optional_region(region) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                Win16HostUpdateOperation::InvalidateRgn {
                    window, region, erase: erase != 0,
                }
            }
            Win16UserUpdateRequest::ValidateRect { window, rect } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let rect = self.read_optional_rect(rect, memory)?;
                Win16HostUpdateOperation::ValidateRect { window, rect }
            }
            Win16UserUpdateRequest::ValidateRgn { window, region } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let Some(region) = self.mapped_optional_region(region) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                Win16HostUpdateOperation::ValidateRgn { window, region }
            }
            Win16UserUpdateRequest::GetUpdateRect { window, rect, erase } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                rect_output = self.prepare_rect_output(rect, memory)?;
                Win16HostUpdateOperation::GetUpdateRect {
                    window,
                    rect_is_null: rect_output.is_none(),
                    erase: erase != 0,
                }
            }
            Win16UserUpdateRequest::GetUpdateRgn { window, region, erase } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let Some(region) = self.guest_gdi.object(region) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                Win16HostUpdateOperation::GetUpdateRgn {
                    window, region, erase: erase != 0,
                }
            }
            Win16UserUpdateRequest::ExcludeUpdateRgn { dc, window } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                Win16HostUpdateOperation::ExcludeUpdateRgn { dc, window }
            }
            Win16UserUpdateRequest::RedrawWindow { window, rect, region, flags } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let Some(region) = self.mapped_optional_region(region) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                // Win16 USER ignores lprcUpdate when a valid HRGN is supplied.
                // Do not touch that guest FAR value in this case.
                let rect = if region.is_some() {
                    None
                } else {
                    self.read_optional_rect(rect, memory)?
                };
                Win16HostUpdateOperation::RedrawWindow { window, rect, region, flags }
            }
            Win16UserUpdateRequest::LockWindowUpdate { window } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                Win16HostUpdateOperation::LockWindowUpdate { window }
            }
            Win16UserUpdateRequest::ScrollWindow {
                window, dx, dy, scroll_rect, clip_rect,
            } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let scroll_rect = self.read_optional_rect(scroll_rect, memory)?;
                let clip_rect = self.read_optional_rect(clip_rect, memory)?;
                Win16HostUpdateOperation::ScrollWindow {
                    window, dx, dy, scroll_rect, clip_rect,
                }
            }
            Win16UserUpdateRequest::ScrollDC {
                dc, dx, dy, scroll_rect, clip_rect, update_region, update_rect,
            } => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let scroll_rect = self.read_optional_rect(scroll_rect, memory)?;
                let clip_rect = self.read_optional_rect(clip_rect, memory)?;
                let Some(update_region) = self.mapped_optional_region(update_region) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                rect_output = self.prepare_rect_output(update_rect, memory)?;
                Win16HostUpdateOperation::ScrollDC {
                    dc, dx, dy, scroll_rect, clip_rect, update_region,
                    update_rect_is_null: rect_output.is_none(),
                }
            }
            Win16UserUpdateRequest::ScrollWindowEx {
                window, dx, dy, scroll_rect, clip_rect, update_region, update_rect, flags,
            } => {
                let Some(window) = self.mapped_window(window) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                let scroll_rect = self.read_optional_rect(scroll_rect, memory)?;
                let clip_rect = self.read_optional_rect(clip_rect, memory)?;
                let Some(update_region) = self.mapped_optional_region(update_region) else {
                    return self.immediate_zero(registers, return_to, return_kind);
                };
                rect_output = self.prepare_rect_output(update_rect, memory)?;
                Win16HostUpdateOperation::ScrollWindowEx {
                    window, dx, dy, scroll_rect, clip_rect, update_region,
                    update_rect_is_null: rect_output.is_none(), flags,
                }
            }
        };

        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::UpdateRegion(operation),
            WindowReturn::UpdateRegion(Win16UpdateContinuation {
                result_kind,
                return_kind,
                rect_output,
            }),
            return_to,
        )
    }

    fn immediate_zero(
        &mut self,
        registers: &mut guest_core::Registers,
        return_to: (u16, u16, u32),
        return_kind: Win16ReturnKind,
    ) -> Result<Option<u8>, RuntimeError> {
        self.complete_return(registers, return_to.0, return_to.1, return_to.2, 0, return_kind)
    }

    /// Zero HWND and HRGN are native null arguments; an unmapped nonzero
    /// guest handle is a normal failed API call and never becomes null.
    fn mapped_window(&self, guest: u16) -> Option<Option<Win16HostWindow>> {
        if guest == 0 {
            Some(None)
        } else {
            self.window_handles.get(&guest).copied().map(Some)
        }
    }

    fn mapped_optional_region(
        &self,
        guest: u16,
    ) -> Option<Option<Win16HostGdiObject>> {
        if guest == 0 {
            Some(None)
        } else {
            self.guest_gdi.object(guest).map(Some)
        }
    }

    fn read_optional_rect(
        &self,
        far: u32,
        memory: &Memory,
    ) -> Result<Option<Win16HostRect>, RuntimeError> {
        if far == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        let mut bytes = [0; Rect16::SIZE];
        self.selectors.read(memory, pointer, &mut bytes).map_err(crate::runtime_error)?;
        Ok(Some(host_rect(Rect16::decode(&bytes))))
    }

    fn prepare_rect_output(
        &self,
        far: u32,
        memory: &Memory,
    ) -> Result<Option<GuestOutputRange>, RuntimeError> {
        if far == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Write, Rect16::SIZE, memory)
            .map_err(crate::runtime_error)?;
        Ok(Some(GuestOutputRange::capture(self, memory, pointer, Rect16::SIZE)?))
    }

}

fn result_shape(request: Win16UserUpdateRequest) -> (UpdateResultKind, Win16ReturnKind) {
    use Win16UserUpdateRequest as Request;
    match request {
        Request::UpdateWindow { .. }
        | Request::InvalidateRect { .. }
        | Request::InvalidateRgn { .. }
        | Request::ValidateRect { .. }
        | Request::ValidateRgn { .. }
        | Request::ScrollWindow { .. } => (UpdateResultKind::Void, Win16ReturnKind::Void),
        Request::GetUpdateRect { .. } | Request::ScrollWindowEx { .. }
        | Request::ScrollDC { .. } => {
            (UpdateResultKind::Rect, Win16ReturnKind::Word)
        }
        Request::GetUpdateRgn { .. }
        | Request::ExcludeUpdateRgn { .. }
        | Request::RedrawWindow { .. }
        | Request::LockWindowUpdate { .. } => (UpdateResultKind::Word, Win16ReturnKind::Word),
    }
}

fn host_rect(rect: Rect16) -> Win16HostRect {
    Win16HostRect {
        left: i32::from(rect.left),
        top: i32::from(rect.top),
        right: i32::from(rect.right),
        bottom: i32::from(rect.bottom),
    }
}

#[cfg(test)]
#[path = "win16_user_services_scroll_dc_tests.rs"]
mod scroll_dc_tests;
