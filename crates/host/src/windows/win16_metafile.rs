//! Classic WMF loading, playback and copying with temporary native ownership.

use std::io::{Read, Write};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostFileSystemPath,
    Win16HostMetafileOperation as Operation, Win16HostMetafileResult as ResultValue};
use windows_sys::Win32::Graphics::Gdi::{
    CopyMetaFileW, DeleteMetaFile, GetMetaFileBitsEx, HMETAFILE, PlayMetaFile, SetMetaFileBitsEx,
};

use crate::filesystem::Filesystem;
use super::win16_gdi::Win16Dcs;

#[path = "win16_metafile_format.rs"]
mod format;

struct NativeMetafile(HMETAFILE);

impl Drop for NativeMetafile {
    fn drop(&mut self) {
        // The only retained native handle is the private object returned by
        // SetMetaFileBitsEx/CopyMetaFileW, never a guest handle or pointer.
        unsafe { DeleteMetaFile(self.0); }
    }
}

impl NativeMetafile {
    fn from_bits(bits: &[u8]) -> Option<Self> {
        let bits = format::validate(bits)?.bytes;
        let count = u32::try_from(bits.len()).ok()?;
        // SAFETY: fixed framing was checked against the complete owned slice.
        // Native GDI owns all record interpretation and copies this input.
        let native = unsafe { SetMetaFileBitsEx(count, bits.as_ptr()) };
        if native.is_null() { None } else { Some(Self(native)) }
    }

    fn copy(&self) -> Option<Self> {
        // NULL requests an independent in-memory object; filename IO remains
        // under the existing capability filesystem, never native path reopen.
        let native = unsafe { CopyMetaFileW(self.0, std::ptr::null()) };
        if native.is_null() { None } else { Some(Self(native)) }
    }

    fn bits(&self, maximum_bytes: u32) -> Option<Vec<u8>> {
        let count = unsafe { GetMetaFileBitsEx(self.0, 0, std::ptr::null_mut()) };
        if count == 0 || count > maximum_bytes { return None; }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(count as usize).ok()?;
        bytes.resize(count as usize, 0);
        if unsafe { GetMetaFileBitsEx(self.0, count, bytes.as_mut_ptr().cast()) } != count {
            return None;
        }
        if format::validate(&bytes)?.bytes.len() != bytes.len() { return None; }
        // The disk representation is a complete memory-format WMF stream.
        // A native file-backed object's private descriptor is never exported.
        bytes[..2].copy_from_slice(&1u16.to_le_bytes());
        Some(bytes)
    }
}

pub(super) fn execute(
    dcs: &Win16Dcs, filesystem: &mut Filesystem, operation: Operation,
) -> Result<ResultValue, RuntimeError> {
    match operation {
        Operation::Get { path, maximum_bytes } => {
            let Some(path) = confined_path(filesystem, path, false) else {
                return Ok(ResultValue::Bits(None));
            };
            // cap-std keeps Unicode path resolution and the opened file under
            // the mounted root, including symlinks and the final open itself.
            let Ok(mut file) = filesystem.root.open(path) else {
                return Ok(ResultValue::Bits(None));
            };
            let bits = read_metafile(&mut file, maximum_bytes)
                .and_then(|bits| NativeMetafile::from_bits(&bits))
                .and_then(|metafile| metafile.bits(maximum_bytes));
            Ok(ResultValue::Bits(bits))
        }
        Operation::CopyToFile { bits, path, maximum_bytes } => {
            let copied = NativeMetafile::from_bits(&bits)
                .and_then(|metafile| metafile.copy())
                .and_then(|metafile| metafile.bits(maximum_bytes));
            let Some(copied) = copied else { return Ok(ResultValue::Bits(None)); };
            let Some(path) = confined_path(filesystem, path, true) else {
                return Ok(ResultValue::Bits(None));
            };
            let mut options = cap_std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            let Ok(mut file) = filesystem.root.open_with(path, &options) else {
                return Ok(ResultValue::Bits(None));
            };
            if file.write_all(&copied).is_err() {
                return Ok(ResultValue::Bits(None));
            }
            Ok(ResultValue::Bits(Some(copied)))
        }
        Operation::Play { dc, bits } => {
            let Some(framed) = format::validate(&bits) else {
                return Ok(ResultValue::Played(false));
            };
            if framed.has_escape {
                // META_ESCAPE can carry callback pointers or driver-specific
                // structures. Those need their own typed Win16/native ABI;
                // passing record bytes to native Escape would bypass the
                // existing bounded printer Escape bridge. Comments can also
                // contain an embedded enhanced metafile with its own escapes.
                return Err(RuntimeError::new(Kind::CompatibilityGap,
                    "WMF Escape records require a typed native payload translation"));
            }
            let Some(native) = NativeMetafile::from_bits(framed.bytes) else {
                return Ok(ResultValue::Played(false));
            };
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Played(false));
            };
            // The exact HDC remains pinned with no table mutex held. No guest
            // abort procedure is registered: SetAbortProc currently reports
            // its unsupported callback contract at its existing entrypoint.
            Ok(ResultValue::Played(unsafe { PlayMetaFile(dc_use.native(), native.0) != 0 }))
        }
    }
}

fn confined_path(
    filesystem: &mut Filesystem, path: runtime::Win16GuestPath, allow_missing: bool,
) -> Option<std::path::PathBuf> {
    let path = filesystem.resolve_win16_host_path(&Win16HostFileSystemPath::Guest(path)).ok()?;
    filesystem.confined_path(&path, true, allow_missing).ok()
}

fn read_metafile(reader: &mut impl Read, maximum_bytes: u32) -> Option<Vec<u8>> {
    let mut header = [0; format::HEADER_BYTES];
    reader.read_exact(&mut header).ok()?;
    // Accept the 22-byte Aldus placeable wrapper before the WMF stream. Its
    // bounding box is external to the WMF; callers choose the target mapping.
    if header[..4] == 0x9ac6_cdd7u32.to_le_bytes() {
        reader.read_exact(&mut [0; 4]).ok()?;
        reader.read_exact(&mut header).ok()?;
    }
    let length = format::byte_length(&header)?;
    if length > maximum_bytes as usize { return None; }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).ok()?;
    bytes.extend_from_slice(&header);
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes[format::HEADER_BYTES..]).ok()?;
    format::validate(&bytes)?;
    Some(bytes)
}
