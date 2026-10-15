//! Win16 USER paint calls and window-scoped device-context leases.

use guest_core::{Registers, memory::Memory};
use win16_abi::{Access, Win16ReturnKind, user_service_abi::{PaintStruct16, Rect16}};

use super::{Win16State, windows::WindowReturn};
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostPaintInfo, Win16HostRect, Win16WindowOperation,
};

impl Win16State {
    /// Starts GetDC or GetWindowDC through the native window worker for a
    /// mapped window. A null HWND retains the existing screen-DC path, where
    /// acquisition and ReleaseDC run on the same runtime thread.
    pub(super) fn begin_user_get_dc(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        window: u16,
        whole_window: bool,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if window == 0 {
            let dc = self.get_dc(0, whole_window, host)?;
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2,
                u32::from(dc), Win16ReturnKind::Word,
            );
        }
        let Some(native_window) = self.window_handles.get(&window).copied() else {
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, 0,
                Win16ReturnKind::Word,
            );
        };
        let Some(guest_dc_reserved) = self.guest_gdi.reserve_dc() else {
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, 0,
                Win16ReturnKind::Word,
            );
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::AcquireWindowDc {
                window: Some(native_window),
                whole_window,
            },
            WindowReturn::AcquireWindowDc {
                guest_dc_reserved,
                native_window,
                consumed_region: None,
            },
            return_to,
        )
    }

    pub(super) fn begin_user_get_dc_ex(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        window: u16,
        region: u16,
        flags: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        // USER ignores hrgnClip without either region flag. Never turn an
        // ignored guest word into a host object identity.
        let region = if flags & 0xc0 != 0 && region != 0 {
            match self.guest_gdi.object(region) {
                Some(region) => Some(region),
                None => return self.complete_return(
                    registers, return_to.0, return_to.1, return_to.2, 0,
                    Win16ReturnKind::Word,
                ),
            }
        } else { None };
        let native_window = if window == 0 { None } else {
            match self.window_handles.get(&window).copied() {
                Some(window) => Some(window),
                None => return self.complete_return(
                    registers, return_to.0, return_to.1, return_to.2, 0,
                    Win16ReturnKind::Word,
                ),
            }
        };
        let Some(guest_dc_reserved) = self.guest_gdi.reserve_dc() else {
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, 0,
                Win16ReturnKind::Word,
            );
        };
        if let Some(native_window) = native_window {
            return self.begin_window_operation(
                registers, memory, host,
                Win16WindowOperation::AcquireWindowDcEx {
                    window: native_window, region, flags,
                },
                WindowReturn::AcquireWindowDc {
                    guest_dc_reserved, native_window, consumed_region: region,
                },
                return_to,
            );
        }
        // Desktop DC acquisition cannot call a guest window procedure. Keep
        // it on the runtime thread, matching the existing ReleaseDC(NULL).
        let acquired = match host.win16_acquire_screen_dc_ex(region, flags) {
            Ok(acquired) => acquired,
            Err(error) => {
                self.guest_gdi.cancel_dc(guest_dc_reserved);
                return Err(error);
            }
        };
        let dc = if let Some(native_dc) = acquired {
            if let Some(region) = region { self.guest_gdi.retire_object_aliases(region); }
            if !self.guest_gdi.bind_dc(guest_dc_reserved, native_dc) {
                let released = host.win16_release_screen_dc(native_dc)?;
                return Err(RuntimeError::new(Kind::InternalInvariant, if released {
                    "GetDCEx lost its reserved guest HDC"
                } else {
                    "GetDCEx lost its reserved guest HDC and could not release the screen DC"
                }));
            }
            guest_dc_reserved
        } else {
            self.guest_gdi.cancel_dc(guest_dc_reserved);
            0
        };
        self.complete_return(
            registers, return_to.0, return_to.1, return_to.2,
            u32::from(dc), Win16ReturnKind::Word,
        )
    }

    /// Begins painting through the existing window-operation continuation.
    /// BeginPaint may synchronously call the window procedure for background
    /// erasure, so no blocking host call is made from the dispatcher.
    pub(super) fn begin_paint(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        window: u16,
        paint_output: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(native_window) = self.window_handles.get(&window).copied() else {
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, 0,
                Win16ReturnKind::Word,
            );
        };
        let output = self.selectors.pointer_from_far(paint_output)
            .map_err(crate::runtime_error)?;
        self.selectors.translate(output, Access::Write, PaintStruct16::SIZE, memory)
            .map_err(crate::runtime_error)?;
        let output = super::guest_ranges::GuestOutputRange::capture(
            self, memory, output, PaintStruct16::SIZE,
        )?;
        let Some(guest_dc_reserved) = self.guest_gdi.reserve_dc() else {
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, 0,
                Win16ReturnKind::Word,
            );
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::BeginPaint { window: native_window },
            WindowReturn::Paint {
                guest_dc_reserved,
                output,
                native_window,
            },
            return_to,
        )
    }

    /// Ends a BeginPaint lease via the HWND-owning worker. The guest HDC is
    /// translated before queuing; the host validates that its token is a paint
    /// DC for this exact window before calling EndPaint.
    pub(super) fn begin_end_paint(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        window: u16,
        paint_far: u32,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(native_window) = self.window_handles.get(&window).copied() else {
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, 0,
                Win16ReturnKind::Void,
            );
        };
        let pointer = self.selectors.pointer_from_far(paint_far)
            .map_err(crate::runtime_error)?;
        let bytes = self.read_text_bytes(memory, pointer, PaintStruct16::SIZE)?;
        let encoded: [u8; PaintStruct16::SIZE] = bytes.try_into().map_err(|_| {
            RuntimeError::new(Kind::InternalInvariant,
                "Win16 PAINTSTRUCT read returned a different byte count")
        })?;
        let paint = PaintStruct16::decode(&encoded);
        let Some(native_dc) = self.guest_gdi.dc(paint.hdc) else {
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, 0,
                Win16ReturnKind::Void,
            );
        };
        let info = paint_info_from_guest(paint);
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::EndPaint { window: native_window, dc: native_dc, info },
            WindowReturn::EndPaint { guest_dc: paint.hdc, native_dc },
            return_to,
        )
    }

    /// Releases a borrowed GetDC/GetWindowDC HDC through the same HWND worker
    /// that acquired it. Paint DCs are rejected by the host lease-kind check.
    pub(super) fn begin_user_release_dc(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        window: u16,
        guest_dc: u16,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        if window == 0 {
            let result = self.release_dc(0, guest_dc, host)?;
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2,
                u32::from(result), Win16ReturnKind::Word,
            );
        }
        let Some(native_window) = self.window_handles.get(&window).copied() else {
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, 0,
                Win16ReturnKind::Word,
            );
        };
        let Some(native_dc) = self.guest_gdi.dc(guest_dc) else {
            return self.complete_return(
                registers, return_to.0, return_to.1, return_to.2, 0,
                Win16ReturnKind::Word,
            );
        };
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::ReleaseWindowDc { window: Some(native_window), dc: native_dc },
            WindowReturn::ReleaseWindowDc { guest_dc, native_dc },
            return_to,
        )
    }

}

pub(in crate::win16_runtime) fn paintstruct_from_host(
    handle: u16,
    paint: Win16HostPaintInfo,
) -> PaintStruct16 {
    PaintStruct16 {
        hdc: handle,
        f_erase: if paint.erase { 1 } else { 0 },
        rc_paint: Rect16 {
            left: guest_coordinate(paint.rect.left),
            top: guest_coordinate(paint.rect.top),
            right: guest_coordinate(paint.rect.right),
            bottom: guest_coordinate(paint.rect.bottom),
        },
        f_restore: if paint.restore { 1 } else { 0 },
        f_inc_update: if paint.inc_update { 1 } else { 0 },
        rgb_reserved: paint.reserved,
    }
}

/// Host desktop/window coordinates can exceed the signed Win16 coordinate
/// range. Saturate at the guest ABI boundary instead of wrapping across the
/// screen; ordinary 16-bit-era coordinates are unchanged.
pub(super) fn guest_coordinate(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

fn paint_info_from_guest(paint: PaintStruct16) -> Win16HostPaintInfo {
    Win16HostPaintInfo {
        erase: paint.f_erase != 0,
        rect: Win16HostRect {
            left: i32::from(paint.rc_paint.left),
            top: i32::from(paint.rc_paint.top),
            right: i32::from(paint.rc_paint.right),
            bottom: i32::from(paint.rc_paint.bottom),
        },
        restore: paint.f_restore != 0,
        inc_update: paint.f_inc_update != 0,
        reserved: paint.rgb_reserved,
    }
}
