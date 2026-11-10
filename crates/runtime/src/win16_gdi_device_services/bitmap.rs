//! GDI bitmap services used by the Win16 device request decoder.

use super::*;

impl Win16State {
    pub(in super::super) fn create_discardable_bitmap(
        &mut self,
        guest_dc: u16,
        width: i16,
        height: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(0);
        };
        match host.win16_gdi_device(Operation::CreateDiscardableBitmap { dc, width, height })? {
            HostResult::Object(Some(object)) => {
                self.allocate_guest_gdi_object(object, host).map(u32::from)
            }
            HostResult::Object(None) => Ok(0),
            _ => Err(wrong_device_result("CreateDiscardableBitmap")),
        }
    }

    pub(super) fn wing_stretch_blt(
        &mut self,
        destination: u16,
        destination_x: i16,
        destination_y: i16,
        destination_width: i16,
        destination_height: i16,
        source: u16,
        source_x: i16,
        source_y: i16,
        source_width: i16,
        source_height: i16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let (Some(destination), Some(source)) =
            (self.guest_gdi.dc(destination), self.guest_gdi.dc(source))
        else {
            return Ok(0);
        };
        match host.win16_gdi_device(Operation::WinGStretchBlt {
            destination,
            destination_x,
            destination_y,
            destination_width,
            destination_height,
            source,
            source_x,
            source_y,
            source_width,
            source_height,
        })? {
            HostResult::Bool(value) => Ok(u32::from(value)),
            _ => Err(wrong_device_result("WinGStretchBlt")),
        }
    }

    pub(super) fn bitmap_dimension(
        &mut self,
        memory: &mut Memory,
        bitmap: u16,
        mode: BitmapDimensionMode,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(bitmap) = self.guest_gdi.object(bitmap) else {
            return Ok(0);
        };

        // SetBitmapDimensionEx documents lpSize as optional, while the Get
        // form requires a writable SIZE. Legacy Get/Set return their packed
        // previous dimensions and never accept this output buffer.
        let output = match mode {
            BitmapDimensionMode::ExtendedGet { output } => Some(output),
            BitmapDimensionMode::ExtendedSet { output, .. } if output != 0 => Some(output),
            _ => None,
        };
        let prepared_output = if let Some(output) = output {
            let pointer = self
                .selectors
                .pointer_from_far(output)
                .map_err(crate::runtime_error)?;
            Some(self.prepare_text_write(memory, pointer, 4)?)
        } else {
            None
        };
        let operation = match mode {
            BitmapDimensionMode::LegacySet { width, height }
            | BitmapDimensionMode::ExtendedSet { width, height, .. } => {
                Operation::SetBitmapDimension {
                    bitmap,
                    width,
                    height,
                }
            }
            BitmapDimensionMode::LegacyGet | BitmapDimensionMode::ExtendedGet { .. } => {
                Operation::GetBitmapDimension { bitmap }
            }
        };
        let HostResult::Point { success, x, y } = host.win16_gdi_device(operation)? else {
            return Err(wrong_device_result("bitmap dimension"));
        };

        if matches!(
            mode,
            BitmapDimensionMode::ExtendedGet { .. } | BitmapDimensionMode::ExtendedSet { .. }
        ) {
            if !success {
                return Ok(0);
            }
            if let Some(prepared) = prepared_output {
                let x_bytes = (x as i16).to_le_bytes();
                let y_bytes = (y as i16).to_le_bytes();
                prepared.commit(memory, &[x_bytes[0], x_bytes[1], y_bytes[0], y_bytes[1]])?;
            }
            return Ok(1);
        }
        if matches!(mode, BitmapDimensionMode::LegacyGet) {
            // Windows 3.1 Programmer's Reference, Volume 2: GDI.162 returns
            // the width in the low word and the height in the high word.
            // Both are signed ints, in 0.1 mm units. Zero is the published
            // result when those dimensions are unavailable. Learn stores the
            // same fields as 32-bit SIZE members and returns zero on failure.
            // A LONG outside the signed int is not that word, so the call
            // returns zero instead of the truncated bits.
            return Ok(legacy_bitmap_dimension(success, x, y));
        }
        Ok(if success {
            pack_words(x as i16, y as i16)
        } else {
            0
        })
    }
}

fn legacy_bitmap_dimension(success: bool, width: i32, height: i32) -> u32 {
    if !success {
        return 0;
    }
    let Ok(width) = i16::try_from(width) else {
        return 0;
    };
    let Ok(height) = i16::try_from(height) else {
        return 0;
    };
    pack_words(width, height)
}
