//! GDI objects services used by the Win16 device request decoder.

use super::*;

impl Win16State {
    pub(super) fn create_wing_halftone_brush(
        &mut self,
        dc: u16,
        color: u32,
        dither_type: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let pattern = match dither_type {
            0 => Win16DitherPattern::Dispersed4x4,
            1 => Win16DitherPattern::Dispersed8x8,
            2 => Win16DitherPattern::Clustered4x4,
            _ => return Ok(0),
        };
        let Some(dc) = self.guest_gdi.dc(dc) else {
            return Ok(0);
        };
        match host.win16_gdi_device(Operation::CreateWinGHalftoneBrush { dc, color, pattern })? {
            HostResult::Object(Some(object)) => {
                self.allocate_guest_gdi_object(object, host).map(u32::from)
            }
            HostResult::Object(None) => Ok(0),
            _ => Err(wrong_device_result("WinGCreateHalfToneBrush")),
        }
    }

    pub(in crate::win16_runtime) fn allocate_guest_gdi_object(
        &mut self,
        object: Win16HostGdiObject,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if let Some(handle) = self.guest_gdi.allocate_object(object) {
            return Ok(handle);
        }
        if !host.win16_delete_object(object)? {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "new Win16 GDI object could not be released after guest handle exhaustion",
            ));
        }
        Ok(0)
    }
}
