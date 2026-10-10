//! Repository-authored NE acceptance fixture; no external Win16 compiler or binary.
//!
//! The byte encodings are the Windows 3.x NE and dialog resource layouts already
//! decoded by `formats` and the runtime. This intentionally tests one hidden
//! modal dialog contract, not application compatibility or visible interaction.
use crate::probe::{CodeBuilder, ProbeBuildError, build_error};

const NE: usize = 0x40;
const CODE: usize = 0x200;
const DATA: usize = 0x400;
const DIALOG: usize = 0x500;
const GROUP: usize = 0x540;
const ICON: usize = 0x560;

/// Emit DIALOG.EXE. Exit 0 requires exactly one WM_INITDIALOG, a nonzero
/// GetDlgItem(10), a nonzero guest STM_GETICON result, and DialogBox result 17.
/// Statuses 1/2/4/5 identify a bad modal result/count/child/icon respectively.
/// EndDialog runs even on a failed child/icon check to avoid leaving a modal UI.
pub fn win16_dialog_probe_bytes() -> Result<Vec<u8>, ProbeBuildError> {
    let (code, fixups) = guest_code()?;
    build_image(&code, &fixups, 6)
}

pub(super) fn build_image(
    code: &[u8],
    fixups: &[[u8; 8]],
    data_length: usize,
) -> Result<Vec<u8>, ProbeBuildError> {
    build_image_with_import(code, fixups, data_length, b"USER", true)
}

/// Shared two-segment NE packaging. Dialog fixtures retain their original
/// offsets; larger generated guests receive an aligned, nonoverlapping DGROUP.
pub(super) fn build_image_with_import(
    code: &[u8],
    fixups: &[[u8; 8]],
    data_length: usize,
    module: &[u8],
    resources: bool,
) -> Result<Vec<u8>, ProbeBuildError> {
    if module.is_empty() || module.len() > 4 || code.len() > u16::MAX as usize
        || data_length == 0 || data_length > 0x1000 || fixups.len() > u16::MAX as usize {
        return Err(build_error("invalid generated Win16 probe layout"));
    }
    let data = (CODE + code.len() + 2 + fixups.len() * 8).max(DATA).next_multiple_of(256);
    let dialog_offset = data + (DIALOG - DATA);
    let group_offset = data + (GROUP - DATA);
    let icon_offset = data + (ICON - DATA);
    if resources && data_length > DIALOG - DATA {
        return Err(build_error("Win16 probe data overlaps its resources"));
    }
    let dialog = dialog_template();
    let icon = icon_image();
    let group = icon_group(icon.len() as u32);
    let length = if resources { icon_offset + icon.len() } else { data + data_length };
    if length > u16::MAX as usize {
        return Err(build_error("generated Win16 probe exceeds its bounded image layout"));
    }
    let mut image = vec![0; length];
    image[..2].copy_from_slice(b"MZ");
    word(&mut image, 2, (length % 512) as u16);
    word(&mut image, 4, image_len_pages(length));
    word(&mut image, 8, 4);
    word(&mut image, 0x18, 0x40);
    dword(&mut image, 0x3c, NE as u32);
    image[NE..NE + 2].copy_from_slice(b"NE");
    word(&mut image, NE + 0x04, 0xa0); // empty entry table
    word(&mut image, NE + 0x06, 1);
    word(&mut image, NE + 0x0c, 0x0301); // Windows GUI, single automatic data segment
    word(&mut image, NE + 0x0e, 2);
    word(&mut image, NE + 0x12, 0x1000); // stack reserve
    word(&mut image, NE + 0x16, 1); // CS:IP = segment 1:0
    word(&mut image, NE + 0x18, 0x1000);
    word(&mut image, NE + 0x1a, 2); // SS = DGROUP
    word(&mut image, NE + 0x1c, 2);
    word(&mut image, NE + 0x1e, 1); // one ordinal-import module
    word(&mut image, NE + 0x22, 0x40);
    word(&mut image, NE + 0x24, 0x50);
    word(&mut image, NE + 0x26, 0x90);
    word(&mut image, NE + 0x28, 0x91);
    word(&mut image, NE + 0x2a, 0x93);
    word(&mut image, NE + 0x32, 4); // 16-byte segment sectors
    image[NE + 0x36] = 2; // Windows
    word(&mut image, NE + 0x3e, 0x030a);
    for (offset, location, length, flags, memory) in [
        (0x40, CODE, code.len(), 0x0100, code.len()),
        (0x48, data, data_length, 0x0001, 0x1000),
    ] {
        word(&mut image, NE + offset, (location >> 4) as u16);
        word(&mut image, NE + offset + 2, length as u16);
        word(&mut image, NE + offset + 4, flags);
        word(&mut image, NE + offset + 6, memory as u16);
    }
    // Resource alignment zero means byte offsets/lengths (unlike NE segments).
    if resources {
        for (index, (kind, id, offset, length)) in [
            (5, 1, dialog_offset, dialog.len()),
            (14, 7, group_offset, group.len()),
            (3, 9, icon_offset, icon.len()),
        ].into_iter().enumerate() {
            let record = NE + 0x52 + index * 20;
            word(&mut image, record, 0x8000 | kind);
            word(&mut image, record + 2, 1);
            word(&mut image, record + 8, offset as u16);
            word(&mut image, record + 10, length as u16);
            word(&mut image, record + 12, 0x0030); // movable, pure resource
            word(&mut image, record + 14, 0x8000 | id);
        }
    }
    // The zero resource terminator occupies 0x8e..0x90. Resident names,
    // import module name offset, and the entry table terminator are also zero.
    image[NE + 0x93] = module.len() as u8;
    image[NE + 0x94..NE + 0x94 + module.len()].copy_from_slice(module);
    image[CODE..CODE + code.len()].copy_from_slice(code);
    word(&mut image, CODE + code.len(), fixups.len() as u16);
    for (index, fixup) in fixups.iter().enumerate() {
        let offset = CODE + code.len() + 2 + index * 8;
        image[offset..offset + 8].copy_from_slice(fixup);
    }
    if resources {
        image[dialog_offset..dialog_offset + dialog.len()].copy_from_slice(&dialog);
        image[group_offset..group_offset + group.len()].copy_from_slice(&group);
        image[icon_offset..icon_offset + icon.len()].copy_from_slice(&icon);
    }
    Ok(image)
}

fn image_len_pages(length: usize) -> u16 { length.div_ceil(512) as u16 }
fn word(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn dword(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn imported_call(code: &mut CodeBuilder, fixups: &mut Vec<[u8; 8]>, ordinal: u16) {
    code.emit(&[0x9a]); // CALL FAR ptr16:16, resolved by an ordinal NE fixup
    let source = code.position() as u16;
    code.emit(&[0xff, 0xff, 0, 0]); // non-additive chain terminator
    let [lo, hi] = source.to_le_bytes();
    let [ord_lo, ord_hi] = ordinal.to_le_bytes();
    fixups.push([3, 1, lo, hi, 1, 0, ord_lo, ord_hi]);
}

fn guest_code() -> Result<(Vec<u8>, Vec<[u8; 8]>), ProbeBuildError> {
    let mut code = CodeBuilder::default();
    let mut fixups = Vec::new();
    code.emit(&[0x89, 0x3e, 0, 0]); // mov [0], di: preserve startup hInstance
    code.emit(&[0x57, 0x6a, 0, 0x6a, 1, 0x6a, 0, 0x0e, 0x68]);
    // Pascal: hInstance, MAKEINTRESOURCE(1) high then low, owner 0, CS:dlgproc.
    code.emit_offset(0, "dlgproc")?;
    imported_call(&mut code, &mut fixups, 87); // USER.DialogBox
    code.emit(&[0x3d, 17, 0]);
    code.branch(0x75, "bad_result");
    code.emit(&[0x83, 0x3e, 2, 0, 1]); // cmp word [2],1: init callback count
    code.branch(0x75, "bad_count");
    code.emit(&[0xa1, 4, 0, 0xb4, 0x4c, 0xcd, 0x21]); // exit saved failure (0/4/5)
    code.mark("bad_result");
    code.emit(&[0xb8, 1, 0x4c, 0xcd, 0x21]);
    code.mark("bad_count");
    code.emit(&[0xb8, 2, 0x4c, 0xcd, 0x21]);

    code.mark("dlgproc");
    code.emit(&[0x55, 0x89, 0xe5, 0x1e, 0x06, 0x53, 0x56, 0x57]);
    // Preserve Pascal callee-saved registers. DGROUP and stack share segment 2.
    code.emit(&[0x16, 0x1f]); // push ss / pop ds
    // BP+6 lParam low, +8 high, +10 wParam, +12 message, +14 HWND.
    code.emit(&[0x31, 0xc0]); // default FALSE for messages other than WM_INITDIALOG
    code.emit(&[0x81, 0x7e, 12, 0x10, 1]);
    code.branch(0x75, "return");
    code.emit(&[0xff, 0x06, 2, 0]); // inc word [2]
    code.emit(&[0xff, 0x76, 14, 0x6a, 10]);
    imported_call(&mut code, &mut fixups, 91); // GetDlgItem(HWND,10)
    code.emit(&[0x85, 0xc0]);
    code.branch(0x74, "bad_child");
    code.emit(&[0x50, 0x68, 1, 4, 0x6a, 0, 0x6a, 0, 0x6a, 0]);
    imported_call(&mut code, &mut fixups, 111); // SendMessage(HWND,STM_GETICON=0401,0,0)
    code.emit(&[0x85, 0xc0]); // HICON16 must be nonzero in low return word
    code.branch(0x74, "bad_icon");
    code.branch(0xeb, "end_dialog");
    code.mark("bad_child");
    code.emit(&[0xc7, 0x06, 4, 0, 4, 0]);
    code.branch(0xeb, "end_dialog");
    code.mark("bad_icon");
    code.emit(&[0xc7, 0x06, 4, 0, 5, 0]);
    code.mark("end_dialog");
    code.emit(&[0xff, 0x76, 14, 0x6a, 17]);
    imported_call(&mut code, &mut fixups, 88); // always EndDialog(HWND,17)
    code.emit(&[0xb8, 1, 0]); // TRUE from WM_INITDIALOG
    code.mark("return");
    code.emit(&[0x5f, 0x5e, 0x5b, 0x07, 0x1f, 0x5d, 0xca, 10, 0]);
    Ok((code.finish(0)?, fixups))
}

fn dialog_template() -> Vec<u8> {
    let mut bytes = vec![0; 35];
    dword(&mut bytes, 0, 0x8000_0000); // WS_POPUP; deliberately no WS_VISIBLE
    bytes[4] = 1;
    word(&mut bytes, 9, 32);
    word(&mut bytes, 11, 32);
    // Empty menu, standard dialog class, empty title: bytes 13..16.
    word(&mut bytes, 20, 16); // child width
    word(&mut bytes, 22, 16); // child height
    word(&mut bytes, 24, 10);
    dword(&mut bytes, 26, 0x4000_0003); // WS_CHILD | SS_ICON, hidden
    bytes[30..35].copy_from_slice(&[0x82, 0xff, 7, 0, 0]);
    bytes
}

fn icon_group(length: u32) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    word(&mut bytes, 2, 1); // icon group
    word(&mut bytes, 4, 1);
    bytes[6] = 16;
    bytes[7] = 16;
    word(&mut bytes, 10, 1);
    word(&mut bytes, 12, 32);
    dword(&mut bytes, 14, length);
    word(&mut bytes, 18, 9);
    bytes
}

fn icon_image() -> Vec<u8> {
    // BITMAPINFOHEADER + 16x16 BGRA XOR plane + DWORD-aligned 1bpp AND mask.
    // Opaque pixels and an all-zero mask avoid alpha/mask ambiguity.
    let mut bytes = vec![0; 40 + 16 * 16 * 4 + 16 * 4];
    dword(&mut bytes, 0, 40);
    dword(&mut bytes, 4, 16);
    dword(&mut bytes, 8, 32); // XOR+AND height
    word(&mut bytes, 12, 1);
    word(&mut bytes, 14, 32);
    dword(&mut bytes, 20, 16 * 16 * 4);
    for pixel in bytes[40..40 + 16 * 16 * 4].chunks_exact_mut(4) {
        pixel.copy_from_slice(&[0x40, 0x80, 0xc0, 0xff]);
    }
    bytes
}

#[cfg(test)]
mod tests;
