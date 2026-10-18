//! Hidden stock dialog with a named guest RT_GROUP_ICON, not a host resource.
use super::{Code, ne, put};

fn user(code: &mut Code, ordinal: u16) {
    code.emit(&[0x9a]);
    code.imports.push((code.bytes.len() as u16, 2, ordinal));
    code.emit(&[0; 4]);
}

fn push_dialog(code: &mut Code) {
    code.emit(&[0xff, 0x36]);
    code.word(18);
}

pub fn named_dialog_icon_program() -> Vec<u8> {
    let mut code = Code::default();
    code.immediate(0x68, 0);
    code.immediate(0x68, 0);
    code.call(47); // GetModuleHandle(NULL).
    code.emit(&[0x50]); // Instance.
    code.immediate(0x68, 0);
    code.immediate(0x68, 11); // RT_DIALOG ordinal.
    code.immediate(0x68, 0); // Owner.
    code.emit(&[0x0e, 0x68]); // FAR guest DLGPROC in this code segment.
    let procedure_site = code.bytes.len();
    code.word(0);
    user(&mut code, 89); // CreateDialog; template omits WS_VISIBLE.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.immediate(0xa3, 18);
    push_dialog(&mut code);
    code.immediate(0x68, 10);
    code.immediate(0x68, 0x0401); // Win16 STM_GETICON.
    for _ in 0..3 {
        code.immediate(0x68, 0);
    }
    user(&mut code, 101); // SendDlgItemMessage.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84); // Must read a real guest icon handle.
    code.emit(&[0x0b, 0xd2]);
    code.fail_if(0x85); // No native pointer high bits escape.
    push_dialog(&mut code);
    user(&mut code, 53); // DestroyWindow.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.interrupt(0x4c00);

    let procedure = code.bytes.len() as u16;
    code.bytes[procedure_site..procedure_site + 2].copy_from_slice(&procedure.to_le_bytes());
    code.emit(&[0x33, 0xc0, 0x33, 0xd2, 0xca, 10, 0]); // FALSE, Pascal RETF 10.

    let mut bytes = ne(
        "NAMEDICO",
        &code.finish(),
        &[0; 512],
        &["KERNEL", "USER"],
        false,
    );
    let name = b"\x82\xa0Icon";
    let mut dialog = 0_u32.to_le_bytes().to_vec();
    dialog.push(1);
    dialog.extend_from_slice(&[0; 8]);
    dialog.extend_from_slice(&[0; 3]);
    dialog.extend_from_slice(&[0; 8]);
    dialog.extend_from_slice(&10_u16.to_le_bytes());
    dialog.extend_from_slice(&0x4000_0003_u32.to_le_bytes());
    dialog.push(0x82); // Stock STATIC, SS_ICON.
    dialog.extend_from_slice(name);
    dialog.extend_from_slice(&[0, 0]); // Title terminator and no creation data.

    // A Win3 monochrome DIB: two palette entries and DWORD-padded XOR/AND
    // rows. Its doubled height includes the transparency mask.
    let mut icon = vec![0; 40 + 8 + 16 * 4 + 16 * 4];
    icon[..4].copy_from_slice(&40_u32.to_le_bytes());
    icon[4..8].copy_from_slice(&16_i32.to_le_bytes());
    icon[8..12].copy_from_slice(&32_i32.to_le_bytes());
    put(&mut icon, 12, 1);
    put(&mut icon, 14, 1);
    icon[44..47].fill(0xff);
    let mut group = vec![0; 20];
    put(&mut group, 2, 1);
    put(&mut group, 4, 1);
    group[6] = 16;
    group[7] = 16;
    group[8] = 2;
    put(&mut group, 10, 1);
    put(&mut group, 12, 1);
    group[14..18].copy_from_slice(&(icon.len() as u32).to_le_bytes());
    put(&mut group, 18, 9);

    // Existing segment/import tables end below this reserved resource table.
    // With shift zero every resource offset/length is an exact byte count.
    const TABLE: usize = 0x100;
    const NAME: usize = 64; // 2 + 3*(8+12) + terminating type WORD.
    bytes.copy_within(0x90..0x100, 0x150);
    for field in [4, 0x26, 0x28, 0x2a] {
        let value = u16::from_le_bytes(bytes[0x40 + field..0x42 + field].try_into().unwrap());
        put(&mut bytes, 0x40 + field, value + 0xc0);
    }
    bytes[0x90..0x100].fill(0);
    put(&mut bytes, 0x40 + 0x24, (TABLE - 0x40) as u16);
    for (index, (kind, id, payload)) in [
        (14, NAME as u16, group),
        (3, 0x8009, icon),
        (5, 0x800b, dialog),
    ]
    .into_iter()
    .enumerate()
    {
        let offset = bytes.len();
        bytes.extend_from_slice(&payload);
        let entry = TABLE + 2 + index * 20;
        put(&mut bytes, entry, 0x8000 | kind);
        put(&mut bytes, entry + 2, 1);
        put(&mut bytes, entry + 8, offset as u16);
        put(&mut bytes, entry + 10, payload.len() as u16);
        put(&mut bytes, entry + 14, id);
    }
    bytes[TABLE + NAME] = name.len() as u8;
    bytes[TABLE + NAME + 1..TABLE + NAME + 1 + name.len()].copy_from_slice(name);
    bytes
}
