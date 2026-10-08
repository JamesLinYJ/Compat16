use runtime::{DiagnosticKind as Kind, RuntimeError};

pub(super) const FATAL_EXIT_ABORT_ID: u16 = 0x4101;
pub(super) const FATAL_EXIT_BREAK_ID: u16 = 0x4102;
pub(super) const FATAL_EXIT_IGNORE_ID: u16 = 0x4103;

#[repr(C, align(4))]
pub(super) struct AlignedDword([u8; 4]);

/// `windows-sys` declares the native entry point but does not provide an owned
/// variable-length dialog-template builder. This checked encoder writes only
/// the fixed Win32 template fields and the three fixed-label buttons.
pub(super) fn fatal_exit_template(text: &str) -> Result<Vec<AlignedDword>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(512).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate Win16 FatalExit dialog template", error))?;

    // DLGTEMPLATE is 18 bytes followed by menu, class, and UTF-16 title atoms.
    put_u32(&mut bytes, 0x80C8_0880)?; // WS_POPUP|WS_CAPTION|WS_SYSMENU|DS_MODALFRAME|DS_CENTER
    put_u32(&mut bytes, 0)?;
    put_u16(&mut bytes, 4)?;
    put_i16(&mut bytes, 0)?;
    put_i16(&mut bytes, 0)?;
    put_i16(&mut bytes, 228)?;
    put_i16(&mut bytes, 92)?;
    put_u16(&mut bytes, 0)?;
    put_u16(&mut bytes, 0)?;
    put_wide(&mut bytes, "Fatal Exit")?;

    add_dialog_item(&mut bytes, 0x5000_0000, 10, 8, 208, 34, 0x0400, 0x0082, text)?;
    add_dialog_item(
        &mut bytes, 0x5001_0001, 8, 58, 64, 18,
        FATAL_EXIT_ABORT_ID, 0x0080, "Abort",
    )?;
    add_dialog_item(
        &mut bytes, 0x5001_0000, 82, 58, 64, 18,
        FATAL_EXIT_BREAK_ID, 0x0080, "Break",
    )?;
    add_dialog_item(
        &mut bytes, 0x5001_0000, 156, 58, 64, 18,
        FATAL_EXIT_IGNORE_ID, 0x0080, "Ignore",
    )?;

    let words = bytes.len().checked_add(3).ok_or_else(|| RuntimeError::new(
        Kind::ResourceExhausted, "Win16 FatalExit dialog template is too large"))? / 4;
    let mut aligned = Vec::new();
    aligned.try_reserve_exact(words).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "align Win16 FatalExit dialog template", error))?;
    for chunk in bytes.chunks(4) {
        let mut dword = [0; 4];
        dword[..chunk.len()].copy_from_slice(chunk);
        aligned.push(AlignedDword(dword));
    }
    Ok(aligned)
}

fn add_dialog_item(
    bytes: &mut Vec<u8>, style: u32, x: i16, y: i16, width: i16, height: i16,
    id: u16, class_ordinal: u16, title: &str,
) -> Result<(), RuntimeError> {
    let padding = (4 - (bytes.len() & 3)) & 3;
    reserve(bytes, padding)?;
    bytes.resize(bytes.len() + padding, 0);
    put_u32(bytes, style)?;
    put_u32(bytes, 0)?;
    put_i16(bytes, x)?;
    put_i16(bytes, y)?;
    put_i16(bytes, width)?;
    put_i16(bytes, height)?;
    put_u16(bytes, id)?;
    put_u16(bytes, 0xffff)?;
    put_u16(bytes, class_ordinal)?;
    put_wide(bytes, title)?;
    put_u16(bytes, 0)?; // no creation data
    Ok(())
}

fn put_wide(bytes: &mut Vec<u8>, value: &str) -> Result<(), RuntimeError> {
    for unit in value.encode_utf16().chain(std::iter::once(0)) {
        put_u16(bytes, unit)?;
    }
    Ok(())
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) -> Result<(), RuntimeError> {
    reserve(bytes, 4)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) -> Result<(), RuntimeError> {
    reserve(bytes, 2)?;
    bytes.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_i16(bytes: &mut Vec<u8>, value: i16) -> Result<(), RuntimeError> {
    put_u16(bytes, value as u16)
}

fn reserve(bytes: &mut Vec<u8>, additional: usize) -> Result<(), RuntimeError> {
    bytes.try_reserve(additional).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "grow Win16 FatalExit dialog template", error))
}
