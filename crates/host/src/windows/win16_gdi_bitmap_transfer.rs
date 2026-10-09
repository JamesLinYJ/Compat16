//! Native Win16 GDI bitmap and DIB transfer adapters for owned buffers.

use std::{mem::{offset_of, size_of}, ptr};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16GdiBitmapOperation as Operation,
    Win16GdiBitmapResult as ResultValue,
};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RLE4, BI_RLE8, BITMAPINFO, BITMAPINFOHEADER, GetBitmapBits, GetDIBits,
    SetBitmapBits, SetDIBits, SetDIBitsToDevice,
};
use zerocopy::IntoBytes;

use super::win16_gdi::Win16Dcs;
use super::win16_gdi_objects::Win16Objects;

const PARALLEL_DIB_MIN_BYTES: usize = 256 * 1024;

/// Executes one native bitmap-data operation. Guest pointers never cross this
/// boundary; each non-null buffer is owned and DWORD-aligned for the call.
pub(super) fn execute(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    operation: Operation,
    work: &parallel_work::BoundedExecutor,
) -> Result<ResultValue, RuntimeError> {
    match operation {
        Operation::SetBitmapBits { bitmap, bytes } => {
            let Some(native_bitmap) = objects.native_bitmap(bitmap) else {
                return Ok(ResultValue::Count(0));
            };
            let count = i32::try_from(bytes.len()).map_err(|_| RuntimeError::new(
                Kind::InvalidInput, "Win16 SetBitmapBits byte count exceeds the host API range"))?;
            let pointer = if bytes.is_empty() { ptr::null() } else { bytes.as_ptr().cast() };
            // SAFETY: The bitmap is retained by the shared GDI object table;
            // `bytes` is owned until SetBitmapBits returns.
            Ok(ResultValue::Count(unsafe {
                SetBitmapBits(native_bitmap, count as u32, pointer)
            }))
        }
        Operation::GetBitmapBits { bitmap, capacity } => {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(capacity).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "allocate Win16 GetBitmapBits output", error))?;
            bytes.resize(capacity, 0);
            let Some(native_bitmap) = objects.native_bitmap(bitmap) else {
                return Ok(ResultValue::GetBitmapBits { count: 0, bytes });
            };
            let count = i32::try_from(capacity).map_err(|_| RuntimeError::new(
                Kind::InvalidInput, "Win16 GetBitmapBits capacity exceeds the host API range"))?;
            let pointer = if bytes.is_empty() { ptr::null_mut() } else { bytes.as_mut_ptr().cast() };
            // SAFETY: The bitmap is retained by the shared GDI object table;
            // `bytes` is a writable owned buffer of exactly `capacity` bytes.
            let copied = unsafe { GetBitmapBits(native_bitmap, count, pointer) };
            Ok(ResultValue::GetBitmapBits { count: copied, bytes })
        }
        Operation::SetDibits {
            bitmap,
            dc,
            start_scan,
            scan_lines,
            info,
            bits,
            color_usage,
        } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(ResultValue::Count(0)); };
            let Some(native_bitmap) = objects.native_bitmap(bitmap) else {
                return Ok(ResultValue::Count(0));
            };
            let info = aligned_optional(info.as_deref(), work)?;
            let bits = aligned_optional(bits.as_deref(), work)?;
            let info_pointer = info.as_ref().map_or(ptr::null(), |bytes|
                bytes.as_ptr().cast::<BITMAPINFO>());
            let bits_pointer = bits.as_ref().map_or(ptr::null(), |bytes|
                bytes.as_ptr().cast());
            // SAFETY: Non-null pointers address DWORD-aligned owned snapshots
            // retained until SetDIBits returns; the HDC lease is also live,
            // and nullness mirrors the Win16 ABI.
            let count = unsafe {
                SetDIBits(
                    dc_use.native(),
                    native_bitmap,
                    u32::from(start_scan),
                    u32::from(scan_lines),
                    bits_pointer,
                    info_pointer,
                    color_usage,
                )
            };
            Ok(ResultValue::Count(count))
        }
        Operation::GetDibits {
            bitmap,
            dc,
            start_scan,
            scan_lines,
            info,
            bits,
            color_usage,
        } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::GetDibits { count: 0, info, bits });
            };
            let Some(native_bitmap) = objects.native_bitmap(bitmap) else {
                return Ok(ResultValue::GetDibits { count: 0, info, bits });
            };
            let mut info = info.map(|bytes| AlignedBytes::copy_from_with(&bytes, Some(work)))
                .transpose()?;
            let mut bits = bits.map(|bytes| AlignedBytes::copy_from_with(&bytes, Some(work)))
                .transpose()?;

            // RLE output has no capacity argument at the native boundary.
            // Query its required size against an independent copy of the full
            // information table, so a failed or oversized query cannot become
            // guest-visible writeback.
            // This follows Microsoft KB Q81498's GetDIBits size-query guidance:
            // https://jeffpar.github.io/kbarchive/kb/081/Q81498/
            let rle_preflight = match (info.as_ref(), bits.as_ref()) {
                (Some(info), Some(bits)) if bits.byte_length != 0 => {
                    info.rle_header_signature().map(|signature|
                        signature.map(|signature| (signature, bits.byte_length)))
                }
                _ => Ok(None),
            };
            let rle_preflight = match rle_preflight {
                Ok(preflight) => preflight,
                Err(()) => return get_dibits_result(0, info, bits, work),
            };
            if let Some((original_signature, bits_capacity)) = rle_preflight {
                let Some(mut query_info) = info.as_ref()
                    .map(AlignedBytes::try_clone).transpose()? else {
                    return get_dibits_result(0, info, bits, work);
                };
                // SAFETY: The bitmap is retained by its shared table; `dc_use`
                // pins the HDC through both native calls. query_info is an
                // independently owned, complete,
                // DWORD-aligned information table kept alive for this call;
                // the null bits pointer requests metadata only.
                let queried_lines = unsafe {
                    GetDIBits(
                        dc_use.native(),
                        native_bitmap,
                        u32::from(start_scan),
                        u32::from(scan_lines),
                        ptr::null_mut(),
                        query_info.as_mut_ptr().cast::<BITMAPINFO>(),
                        color_usage,
                    )
                };
                let query_signature = query_info.rle_header_signature();
                let required_bytes = query_info.read_u32_at(
                    offset_of!(BITMAPINFOHEADER, biSizeImage),
                );
                let capacity_is_sufficient = queried_lines != 0
                    && query_signature == Ok(Some(original_signature))
                    && required_bytes.is_some_and(|required| {
                        required != 0 && usize::try_from(required).is_ok_and(|required|
                            required <= bits_capacity)
                    });
                if !capacity_is_sufficient {
                    return get_dibits_result(0, info, bits, work);
                }
            }

            let info_pointer = info.as_mut().map_or(ptr::null_mut(), |bytes|
                bytes.as_mut_ptr().cast::<BITMAPINFO>());
            let bits_pointer = bits.as_mut().map_or(ptr::null_mut(), AlignedBytes::as_mut_ptr);
            // SAFETY: Non-null pointers refer to aligned owned buffers retained
            // for the synchronous call; the HDC lease remains live too. Their
            // original extents are preserved when returned to runtime,
            // including untouched trailing bytes.
            let count = unsafe {
                GetDIBits(
                    dc_use.native(),
                    native_bitmap,
                    u32::from(start_scan),
                    u32::from(scan_lines),
                    bits_pointer,
                    info_pointer,
                    color_usage,
                )
            };
            get_dibits_result(count, info, bits, work)
        }
        Operation::SetDibitsToDevice {
            dc,
            destination_x,
            destination_y,
            width,
            height,
            source_x,
            source_y,
            start_scan,
            scan_lines,
            info,
            bits,
            color_usage,
        } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(ResultValue::Count(0)); };
            let info = aligned_optional(info.as_deref(), work)?;
            let bits = aligned_optional(bits.as_deref(), work)?;
            let info_pointer = info.as_ref().map_or(ptr::null(), |bytes|
                bytes.as_ptr().cast::<BITMAPINFO>());
            let bits_pointer = bits.as_ref().map_or(ptr::null(), |bytes|
                bytes.as_ptr().cast());
            // SAFETY: Non-null pointers address DWORD-aligned owned snapshots
            // retained until SetDIBitsToDevice returns; the HDC lease remains
            // live too, and nullness is preserved.
            let count = unsafe {
                SetDIBitsToDevice(
                    dc_use.native(),
                    destination_x,
                    destination_y,
                    width as u32,
                    height as u32,
                    source_x,
                    source_y,
                    u32::from(start_scan),
                    u32::from(scan_lines),
                    bits_pointer,
                    info_pointer,
                    color_usage,
                )
            };
            Ok(ResultValue::Count(count))
        }
    }
}

/// Owned storage for native DIB calls. Vec<u8> has no DWORD-alignment
/// guarantee, and a zero-copy guest view cannot provide fallible aligned
/// scratch allocation; this Vec<u32> retains both alignment and the exact
/// guest byte length across the synchronous call.
pub(super) struct AlignedBytes {
    words: Vec<u32>,
    byte_length: usize,
}

impl AlignedBytes {
    pub(super) fn copy_from(bytes: &[u8]) -> Result<Self, RuntimeError> {
        Self::copy_from_with(bytes, None)
    }

    fn copy_from_with(
        bytes: &[u8],
        work: Option<&parallel_work::BoundedExecutor>,
    ) -> Result<Self, RuntimeError> {
        let padded = bytes.len().checked_add(3).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 native DIB buffer length overflowed"))?;
        let word_count = (padded / 4).max(1);
        let mut words = Vec::new();
        words.try_reserve_exact(word_count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate aligned native Win16 DIB buffer", error))?;
        words.resize(word_count, 0_u32);
        // zerocopy exposes the initialized DWORD allocation without raw
        // pointer casts. Its final padding bytes retain their zero values.
        let output = &mut words.as_mut_slice().as_mut_bytes()[..bytes.len()];
        let convert = |offset: usize, chunk: &mut [u8]| {
            chunk.copy_from_slice(&bytes[offset..offset + chunk.len()]);
        };
        if let Some(work) = work {
            work.for_each_chunk_aligned(output, PARALLEL_DIB_MIN_BYTES, 4, convert);
        } else {
            convert(0, output);
        }
        Ok(Self { words, byte_length: bytes.len() })
    }

    fn try_clone(&self) -> Result<Self, RuntimeError> {
        let mut words = Vec::new();
        words.try_reserve_exact(self.words.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "clone aligned Win16 DIB information table", error))?;
        words.extend_from_slice(&self.words);
        Ok(Self { words, byte_length: self.byte_length })
    }

    fn as_mut_ptr(&mut self) -> *mut core::ffi::c_void {
        self.words.as_mut_ptr().cast()
    }

    pub(super) fn as_ptr(&self) -> *const core::ffi::c_void {
        self.words.as_ptr().cast()
    }

    fn into_bytes(self, work: &parallel_work::BoundedExecutor) -> Result<Vec<u8>, RuntimeError> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(self.byte_length).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "allocate Win16 DIB result bytes", error))?;
        bytes.resize(self.byte_length, 0);
        // Aligned chunk boundaries retain the exact DWORD-to-byte mapping,
        // including a final partial word and untouched guest trailing bytes.
        work.for_each_chunk_aligned(&mut bytes, PARALLEL_DIB_MIN_BYTES, 4,
            |offset, chunk| {
                chunk.copy_from_slice(&self.words.as_slice().as_bytes()
                    [offset..offset + chunk.len()]);
            }
        );
        Ok(bytes)
    }

    fn read_u32_at(&self, offset: usize) -> Option<u32> {
        let field_end = offset.checked_add(size_of::<u32>())?;
        if offset % size_of::<u32>() != 0 || field_end > self.byte_length {
            return None;
        }
        self.words.get(offset / size_of::<u32>()).copied()
    }

    fn read_u16_at(&self, offset: usize) -> Option<u16> {
        let field_end = offset.checked_add(size_of::<u16>())?;
        if field_end > self.byte_length {
            return None;
        }
        let word_index = offset / size_of::<u32>();
        let byte_index = offset % size_of::<u32>();
        let bytes = self.words.get(word_index)?.to_ne_bytes();
        let field = bytes.get(byte_index..byte_index.checked_add(size_of::<u16>())?)?;
        Some(u16::from_ne_bytes(field.try_into().ok()?))
    }

    fn read_i32_at(&self, offset: usize) -> Option<i32> {
        self.read_u32_at(offset).map(|value| i32::from_ne_bytes(value.to_ne_bytes()))
    }

    fn rle_header_signature(&self) -> Result<Option<RleHeaderSignature>, ()> {
        let declared_header_size = self.read_u32_at(offset_of!(BITMAPINFOHEADER, biSize))
            .ok_or(())?;
        if usize::try_from(declared_header_size).map_err(|_| ())?
            < size_of::<BITMAPINFOHEADER>()
        {
            // Includes the 12-byte BITMAPCOREHEADER form; it has no compression
            // member and must stay on the original, non-RLE path.
            return Ok(None);
        }
        if usize::try_from(declared_header_size).map_err(|_| ())? > self.byte_length {
            return Err(());
        }

        let compression = self.read_u32_at(offset_of!(BITMAPINFOHEADER, biCompression))
            .ok_or(())?;
        if compression != BI_RLE4 && compression != BI_RLE8 {
            return Ok(None);
        }
        Ok(Some(RleHeaderSignature {
            compression,
            width: self.read_i32_at(offset_of!(BITMAPINFOHEADER, biWidth)).ok_or(())?,
            height: self.read_i32_at(offset_of!(BITMAPINFOHEADER, biHeight)).ok_or(())?,
            planes: self.read_u16_at(offset_of!(BITMAPINFOHEADER, biPlanes)).ok_or(())?,
            bit_count: self.read_u16_at(offset_of!(BITMAPINFOHEADER, biBitCount)).ok_or(())?,
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RleHeaderSignature {
    compression: u32,
    width: i32,
    height: i32,
    planes: u16,
    bit_count: u16,
}

fn get_dibits_result(
    count: i32,
    info: Option<AlignedBytes>,
    bits: Option<AlignedBytes>,
    work: &parallel_work::BoundedExecutor,
) -> Result<ResultValue, RuntimeError> {
    Ok(ResultValue::GetDibits {
        count,
        info: info.map(|bytes| bytes.into_bytes(work)).transpose()?,
        bits: bits.map(|bytes| bytes.into_bytes(work)).transpose()?,
    })
}

fn aligned_optional(
    bytes: Option<&[u8]>,
    work: &parallel_work::BoundedExecutor,
) -> Result<Option<Vec<u32>>, RuntimeError> {
    bytes.map(|bytes| AlignedBytes::copy_from_with(bytes, Some(work))
        .map(|aligned| aligned.words)).transpose()
}
