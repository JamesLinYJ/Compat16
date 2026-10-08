//! Checked guest-memory reads for Win16 DIB APIs.

use guest_core::memory::Memory;
use win16_abi::gdi_dib::{
    DibLayout16, DibLayoutError, get_dibits_output_layout, info_layout, validate_info_bytes,
};

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::Win16State;

/// Owned BITMAPINFO header/table bytes paired with their checked Win16 layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Win16GuestDibInfo {
    pub bytes: Vec<u8>,
    pub layout: DibLayout16,
}

impl Win16State {
    /// Copies only a known Win16 DIB header, returning whether the guest's
    /// bit-count field is zero. GetDIBits accepts this header-only form when
    /// `lpvBits` is null and uses it to query the bitmap's format.
    pub(crate) fn copy_dib_header(
        &self,
        memory: &Memory,
        info_far: u32,
    ) -> Result<Option<(Vec<u8>, bool)>, RuntimeError> {
        if info_far == 0 {
            return Ok(None);
        }
        let pointer = self.selectors.pointer_from_far(info_far).map_err(crate::runtime_error)?;
        let prefix = self.read_text_bytes(memory, pointer, 4)?;
        let Some(header_size_bytes) = prefix.get(..4) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 DIB header prefix copy returned an unexpected length"));
        };
        let header_size = u32::from_le_bytes(header_size_bytes.try_into().map_err(|_|
            RuntimeError::new(Kind::InternalInvariant,
                "Win16 DIB header prefix has an unexpected width"))?);
        let header_bytes = usize::try_from(header_size).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "Win16 DIB header exceeds host address space", error))?;
        let bit_count_offset = match header_size {
            12 => 10,
            size if size >= 40 => 14,
            _ => return Ok(None),
        };
        if header_bytes < bit_count_offset + 2 {
            return Ok(None);
        }
        let bytes = self.read_text_bytes(memory, pointer, header_bytes)?;
        let bit_count = bytes.get(bit_count_offset..bit_count_offset + 2)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 DIB header copy omitted its bit-count field"))?;
        Ok(Some((bytes, bit_count == 0)))
    }

    /// Copies a guest BITMAPINFO header and color table after deriving their
    /// extent from the guest header. Malformed structures are ordinary GDI
    /// failures; unreadable non-null pointers remain guest memory faults.
    pub(crate) fn copy_dib_info(
        &self,
        memory: &Memory,
        info_far: u32,
        color_usage: u16,
    ) -> Result<Option<Win16GuestDibInfo>, RuntimeError> {
        self.copy_dib_info_with_layout(memory, info_far, color_usage, info_layout)
    }

    /// GetDIBits may synthesize the complete output palette independently of
    /// biClrUsed. Snapshot its full capacity so untouched bytes are preserved;
    /// the caller also validates this same range for writing before native GDI.
    pub(crate) fn copy_dib_output_info(
        &self,
        memory: &Memory,
        info_far: u32,
        color_usage: u16,
        query_only: bool,
    ) -> Result<Option<Win16GuestDibInfo>, RuntimeError> {
        self.copy_dib_info_with_layout(memory, info_far, color_usage,
            |prefix, usage| get_dibits_output_layout(prefix, usage, query_only))
    }

    fn copy_dib_info_with_layout(
        &self,
        memory: &Memory,
        info_far: u32,
        color_usage: u16,
        decode_layout: impl FnOnce(&[u8], u16) -> Result<DibLayout16, DibLayoutError>,
    ) -> Result<Option<Win16GuestDibInfo>, RuntimeError> {
        if info_far == 0 {
            return Ok(None);
        }
        let pointer = self.selectors.pointer_from_far(info_far).map_err(crate::runtime_error)?;
        let prefix = self.read_text_bytes(memory, pointer, 4)?;
        let header_size_bytes: [u8; 4] = prefix.as_slice().try_into().map_err(|_|
            RuntimeError::new(Kind::InternalInvariant,
                "Win16 DIB prefix copy returned an unexpected length"))?;
        let header_size = u32::from_le_bytes(header_size_bytes);
        let prefix_len = match header_size {
            12 => 12,
            size if size >= 40 => 40,
            _ => return Ok(None),
        };
        let prefix = self.read_text_bytes(memory, pointer, prefix_len)?;
        let Ok(layout) = decode_layout(&prefix, color_usage) else { return Ok(None); };
        let bytes = self.read_text_bytes(memory, pointer, layout.info_bytes())?;
        if validate_info_bytes(&bytes, layout).is_err() {
            return Ok(None);
        }
        Ok(Some(Win16GuestDibInfo { bytes, layout }))
    }

    /// Copies an optional bitmap-bits input or snapshots a caller-owned output
    /// buffer before native GDI is allowed to mutate it. A non-null zero-byte
    /// range retains pointer presence with a one-byte sentinel, while callers
    /// still pass the original zero capacity to native GDI.
    pub(crate) fn copy_dib_bits(
        &self,
        memory: &Memory,
        far: u32,
        length: usize,
    ) -> Result<Option<Vec<u8>>, RuntimeError> {
        if far == 0 {
            return Ok(None);
        }
        if length == 0 {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve zero-length Win16 DIB pointer sentinel",
                error,
            ))?;
            bytes.push(0);
            return Ok(Some(bytes));
        }
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        self.read_text_bytes(memory, pointer, length).map(Some)
    }
}
