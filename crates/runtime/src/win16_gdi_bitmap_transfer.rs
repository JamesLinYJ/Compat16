//! Win16 bitmap and DIB transfers, pointer validation, and guest writeback.

use guest_core::memory::Memory;
use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16GdiBitmapOperation as Operation, Win16GdiBitmapResult as HostResult,
};

impl Win16State {
    pub(super) fn set_bitmap_bits(
        &self,
        bitmap_handle: u16,
        byte_count: i32,
        bytes: Vec<u8>,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if byte_count <= 0 || usize::try_from(byte_count).ok() != Some(bytes.len()) {
            return Ok(0);
        }
        let Some(bitmap) = self.guest_gdi.object(bitmap_handle) else { return Ok(0); };
        match host.win16_gdi_bitmap(Operation::SetBitmapBits { bitmap, bytes })? {
            HostResult::Count(count) => Ok(count as u32),
            _ => Err(wrong_result("SetBitmapBits")),
        }
    }

    pub(super) fn get_bitmap_bits(
        &self,
        memory: &mut Memory,
        bitmap_handle: u16,
        byte_count: i32,
        output_far: u32,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if byte_count <= 0 { return Ok(0); }
        let Some(bitmap) = self.guest_gdi.object(bitmap_handle) else { return Ok(0); };
        let capacity = usize::try_from(byte_count).map_err(|_| RuntimeError::new(
            Kind::InvalidInput, "Win16 GetBitmapBits byte count does not fit host memory"))?;
        let destination = self.selectors.pointer_from_far(output_far).map_err(crate::runtime_error)?;
        let write = self.prepare_text_write(memory, destination, capacity)?;
        let result = host.win16_gdi_bitmap(Operation::GetBitmapBits { bitmap, capacity })?;
        let HostResult::GetBitmapBits { count, bytes } = result else {
            return Err(wrong_result("GetBitmapBits"));
        };
        if count < 0 || usize::try_from(count).map_or(true, |copied| copied > capacity)
            || bytes.len() != capacity
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native GetBitmapBits returned an invalid byte count or buffer extent"));
        }
        write.commit(memory, &bytes[..count as usize])?;
        Ok(count as u32)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn set_dibits(
        &self,
        memory: &Memory,
        bitmap_handle: u16,
        dc_handle: u16,
        start_scan: u16,
        scan_lines: u16,
        bits_far: u32,
        info_far: u32,
        color_usage: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(bitmap) = self.guest_gdi.object(bitmap_handle) else { return Ok(0); };
        let Some(dc) = self.guest_gdi.dc(dc_handle) else { return Ok(0); };
        let Some(info) = self.copy_dib_info(memory, info_far, color_usage)? else {
            // Without the DIB header the bit-buffer extent cannot be bounded.
            return Ok(0);
        };
        let Some(bits_length) = dib_transfer_length(info.layout, scan_lines) else {
            return Ok(0);
        };
        let bits = self.copy_dib_bits(memory, bits_far, bits_length)?;
        match host.win16_gdi_bitmap(Operation::SetDibits {
            bitmap,
            dc,
            start_scan,
            scan_lines,
            info: Some(info.bytes),
            bits,
            color_usage: u32::from(color_usage),
        })? {
            HostResult::Count(count) => Ok(count as u16 as u32),
            _ => Err(wrong_result("SetDIBits")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn get_dibits(
        &self,
        memory: &mut Memory,
        bitmap_handle: u16,
        dc_handle: u16,
        start_scan: u16,
        scan_lines: u16,
        bits_far: u32,
        info_far: u32,
        color_usage: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(bitmap) = self.guest_gdi.object(bitmap_handle) else { return Ok(0); };
        let Some(dc) = self.guest_gdi.dc(dc_handle) else { return Ok(0); };

        // A zero-bit-count query legitimately leaves other fields unset, but
        // it still requires the native color-table format to be valid.
        if !matches!(color_usage,
            win16_abi::gdi_dib::DIB_RGB_COLORS16 | win16_abi::gdi_dib::DIB_PAL_COLORS16)
        {
            return Ok(0);
        }

        let (info, info_length, bits_length) = match self.copy_dib_output_info(
            memory,
            info_far,
            color_usage,
            bits_far == 0,
        )? {
            Some(info) => {
                let bits_length = if bits_far == 0 { Some(0) } else {
                    dib_transfer_length(info.layout, scan_lines)
                };
                (Some(info.bytes), Some(info.layout.info_bytes()), bits_length)
            }
            None if bits_far == 0 => {
                let Some((header, zero_bit_count)) = self.copy_dib_header(memory, info_far)? else {
                    return Ok(0);
                };
                if !zero_bit_count {
                    return Ok(0);
                }
                let length = header.len();
                (Some(header), Some(length), Some(0))
            }
            None => return Ok(0),
        };
        let Some(bits_length) = bits_length else { return Ok(0); };

        let bits = self.copy_dib_bits(memory, bits_far, bits_length)?;
        let info_write = match (info_far, info_length) {
            (0, _) | (_, None) => None,
            (far, Some(length)) => {
                let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
                Some(self.prepare_text_write(memory, pointer, length)?)
            }
        };
        let bits_write = if bits_far == 0 || bits_length == 0 {
            None
        } else {
            let pointer = self.selectors.pointer_from_far(bits_far).map_err(crate::runtime_error)?;
            Some(self.prepare_text_write(memory, pointer, bits_length)?)
        };

        let result = host.win16_gdi_bitmap(Operation::GetDibits {
            bitmap,
            dc,
            start_scan,
            scan_lines,
            info,
            bits,
            color_usage: u32::from(color_usage),
        })?;
        let HostResult::GetDibits { count, info, bits } = result else {
            return Err(wrong_result("GetDIBits"));
        };

        if let Some(info_write) = info_write {
            let Some(bytes) = info.as_deref() else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native GetDIBits dropped a non-null information buffer"));
            };
            if bytes.len() != info_length.unwrap_or_default() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native GetDIBits changed the information buffer extent"));
            }
            info_write.commit(memory, bytes)?;
        }
        if let Some(bits_write) = bits_write {
            let Some(bytes) = bits.as_deref() else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native GetDIBits dropped a non-null bits buffer"));
            };
            if bytes.len() != bits_length {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native GetDIBits changed the bits buffer extent"));
            }
            bits_write.commit(memory, bytes)?;
        }
        Ok(count as u16 as u32)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn set_dibits_to_device(
        &self,
        memory: &Memory,
        dc_handle: u16,
        destination_x: i16,
        destination_y: i16,
        width: i16,
        height: i16,
        source_x: i16,
        source_y: i16,
        start_scan: u16,
        scan_lines: u16,
        bits_far: u32,
        info_far: u32,
        color_usage: u16,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if width < 0 || height < 0 { return Ok(0); }
        let Some(dc) = self.guest_gdi.dc(dc_handle) else { return Ok(0); };
        let Some(info) = self.copy_dib_info(memory, info_far, color_usage)? else {
            return Ok(0);
        };
        let Some(bits_length) = dib_transfer_length(info.layout, scan_lines) else {
            return Ok(0);
        };
        let bits = self.copy_dib_bits(memory, bits_far, bits_length)?;
        match host.win16_gdi_bitmap(Operation::SetDibitsToDevice {
            dc,
            destination_x: i32::from(destination_x),
            destination_y: i32::from(destination_y),
            width: i32::from(width),
            height: i32::from(height),
            source_x: i32::from(source_x),
            source_y: i32::from(source_y),
            start_scan,
            scan_lines,
            info: Some(info.bytes),
            bits,
            color_usage: u32::from(color_usage),
        })? {
            HostResult::Count(count) => Ok(count as u16 as u32),
            _ => Err(wrong_result("SetDIBitsToDevice")),
        }
    }
}

fn dib_transfer_length(layout: win16_abi::gdi_dib::DibLayout16, scan_lines: u16)
    -> Option<usize>
{
    match layout.row_bytes() {
        Some(row_bytes) => row_bytes.checked_mul(usize::from(scan_lines)),
        None => Some(layout.bits_bytes),
    }
}

fn wrong_result(operation: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant,
        format!("host returned the wrong result for Win16 {operation}"))
}
