//! Native, aligned METARECORD playback with process-owned handle translation.

use super::super::{win16_gdi::Win16Dcs, win16_gdi_objects::Win16Objects};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostDc, Win16HostGdiObject,
    Win16HostMetafileResult as ResultValue,
};
use windows_sys::Win32::Graphics::Gdi::{
    HANDLETABLE, METARECORD, PlayMetaFileRecord, SelectObject,
};

pub(in crate::windows) fn play(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    dc: Win16HostDc,
    record: Vec<u8>,
    table: Vec<Option<Win16HostGdiObject>>,
) -> Result<ResultValue, RuntimeError> {
    let failure = || ResultValue::Record {
        success: false,
        objects: table.clone(),
        retired: Vec::new(),
    };
    let shape = match formats::validate_wmf_record_playback(&record, table.len()) {
        Ok(shape) => shape,
        Err(_) => return Ok(failure()),
    };
    if shape.creates_object && !table.contains(&None) {
        return Ok(failure());
    }
    let mut native: Vec<windows_sys::Win32::Graphics::Gdi::HGDIOBJ> =
        Vec::with_capacity(table.len().max(1));
    for token in &table {
        native.push(match token {
            None => std::ptr::null_mut(),
            Some(token) => match objects.metafile_object(*token)? {
                Some(handle) => handle as _,
                None => return Ok(failure()),
            },
        });
    }
    if native.is_empty() {
        native.push(std::ptr::null_mut());
    }
    let Some(dc) = dcs.lease_dc(dc)? else {
        return Ok(failure());
    };
    let function = u16::from_le_bytes([record[4], record[5]]);
    let success = if shape.ignored || function == 0 {
        true // Documented unknown-record/EOF no-op; no native pointer is used.
    } else if function == 0x012d && u16::from_le_bytes([record[6], record[7]]) & 0x8000 != 0 {
        let stock = u16::from_le_bytes([record[6], record[7]]) & 0x7fff;
        // Resolve WMF's stock-object encoding without indexing the table.
        let stock = crate::windows::win32_safe::stock_object(i32::from(stock));
        // SAFETY: SelectObject selects a GDI object this process created into a live DC.
        let previous = unsafe { SelectObject(dc.native(), stock) };
        !previous.is_null() && previous as isize != -1
    } else {
        // Vec<u32> supplies native DWORD alignment and at least sizeof
        // METARECORD (its C declaration includes one parameter WORD).
        let mut aligned = vec![0u32; record.len().div_ceil(4).max(2)];
        for (slot, bytes) in aligned.iter_mut().zip(record.chunks(4)) {
            let mut word = [0; 4];
            word[..bytes.len()].copy_from_slice(bytes);
            *slot = u32::from_le_bytes(word);
        }
        // SAFETY: The codec checked every payload and table index consumed by
        // this supported function. Native handles come only from our GDI table;
        // both owned buffers remain aligned and live for this synchronous call.
        (unsafe {
            PlayMetaFileRecord(
                dc.native(),
                native.as_mut_ptr().cast::<HANDLETABLE>(),
                aligned.as_ptr().cast::<METARECORD>(),
                table.len() as u32,
            )
        }) != 0
    };
    let mut retired = Vec::new();
    for token in table.iter().flatten() {
        if objects.retire_metafile_object(*token)? && !retired.contains(token) {
            retired.push(*token);
        }
    }
    let mut output = Vec::with_capacity(table.len());
    for handle in native.into_iter().take(table.len()) {
        output.push(if handle.is_null() {
            None
        } else if let Some(token) = objects.existing_native_token(handle as usize)? {
            Some(token)
        } else if shape.creates_object {
            objects.adopt_owned(handle)?
        } else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "WMF playback introduced an object outside its creation contract",
            ));
        });
    }
    Ok(ResultValue::Record {
        success,
        objects: output,
        retired,
    })
}
