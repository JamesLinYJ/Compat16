//! A hidden child dialog is exposed to its guest parent before WM_INITDIALOG.
use super::{Code, ne, put};

fn user(code: &mut Code, ordinal: u16) {
    code.call(ordinal);
    code.imports.last_mut().unwrap().1 = 2;
}
fn push_memory(code: &mut Code, offset: u16) {
    code.emit(&[0xff, 0x36]);
    code.word(offset);
}
fn branch(code: &mut Code) -> usize {
    code.emit(&[0x0f, 0x85]);
    let site = code.bytes.len();
    code.word(0);
    site
}
fn patch_branch(code: &mut Code, site: usize) {
    let relative = i16::try_from(code.bytes.len() as isize - (site + 2) as isize).unwrap();
    code.bytes[site..site + 2].copy_from_slice(&relative.to_le_bytes());
}

pub fn child_dialog_program() -> Vec<u8> {
    let mut code = Code::default();
    for _ in 0..2 {
        code.immediate(0x68, 0);
    }
    code.call(47); // KERNEL.GetModuleHandle(NULL).
    code.immediate(0xa3, 10); // WNDCLASS16.hInstance.
    code.emit(&[0x8c, 0x0e, 4, 0, 0x8c, 0x1e, 24, 0]); // CS/DS in FAR fields.
    code.emit(&[0x1e]);
    code.immediate(0x68, 0);
    user(&mut code, 57); // RegisterClass.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.emit(&[0x1e]);
    code.immediate(0x68, 0x100); // Class name.
    for value in [0, 0, 0x8000, 0, 0, 0, 80, 80, 0, 0] {
        code.immediate(0x68, value);
    }
    push_memory(&mut code, 10);
    for _ in 0..2 {
        code.immediate(0x68, 0);
    }
    user(&mut code, 41); // CreateWindow, WS_POPUP without WS_VISIBLE.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.immediate(0xa3, 28);
    push_memory(&mut code, 10);
    for value in [0, 11] {
        code.immediate(0x68, value);
    }
    push_memory(&mut code, 28);
    code.emit(&[0x0e, 0x68]);
    let dialog_site = code.bytes.len();
    code.word(0);
    user(&mut code, 89); // CreateDialog's HWND must equal the earlier alias.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.immediate(0xa3, 34);
    for offset in [30, 32] {
        code.emit(&[0x3b, 0x06]);
        code.word(offset);
        code.fail_if(0x85);
    }
    code.emit(&[0x50]);
    code.immediate(0x68, 77);
    user(&mut code, 91); // The custom child also keeps its real root parent.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.emit(&[0x50]);
    user(&mut code, 46); // GetParent.
    code.emit(&[0x3b, 0x06]);
    code.word(34);
    code.fail_if(0x85);
    push_memory(&mut code, 34);
    user(&mut code, 53);
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    push_memory(&mut code, 28);
    user(&mut code, 53);
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.interrupt(0x4c00);

    let parent_proc = code.bytes.len() as u16;
    code.emit(&[0x55, 0x8b, 0xec, 0x81, 0x7e, 12]);
    code.word(0x0210);
    let other_message = branch(&mut code);
    code.emit(&[0x83, 0x7e, 10, 1]);
    let other_event = branch(&mut code);
    code.emit(&[0x83, 0x3e, 30, 0, 0]);
    let already_notified = branch(&mut code);
    code.emit(&[0x8b, 0x46, 6]);
    code.immediate(0xa3, 30); // HWND16 in LPARAM low.
    patch_branch(&mut code, other_message);
    patch_branch(&mut code, other_event);
    patch_branch(&mut code, already_notified);
    for offset in [14, 12, 10, 8, 6] {
        code.emit(&[0xff, 0x76, offset]);
    }
    user(&mut code, 107); // The real DefWindowProc result, including WM_NCCREATE.
    code.emit(&[0x5d, 0xca, 10, 0]);

    let dialog_proc = code.bytes.len() as u16;
    code.bytes[dialog_site..dialog_site + 2].copy_from_slice(&dialog_proc.to_le_bytes());
    code.emit(&[0x55, 0x8b, 0xec, 0x81, 0x7e, 12]);
    code.word(0x0110);
    let other_dialog_message = branch(&mut code);
    code.emit(&[0x8b, 0x46, 14]);
    code.immediate(0xa3, 32);
    patch_branch(&mut code, other_dialog_message);
    code.emit(&[0x33, 0xc0, 0x33, 0xd2, 0x5d, 0xca, 10, 0]);

    let mut data = vec![0_u8; 512];
    put(&mut data, 2, parent_proc);
    put(&mut data, 22, 0x100);
    data[0x100..0x10d].copy_from_slice(b"C16DlgParent\0");
    let mut bytes = ne(
        "CHILDDLG",
        &code.finish(),
        &data,
        &["KERNEL", "USER"],
        false,
    );
    let word = |at| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
    let header_end = 0x40 + usize::from(word(0x44)) + usize::from(word(0x46));
    assert!(header_end + 32 < 0x200);
    bytes.copy_within(0x90..header_end, 0xb0);
    bytes[0x90..0xb0].fill(0);
    for field in [4, 0x26, 0x28, 0x2a] {
        let value = u16::from_le_bytes(bytes[0x40 + field..0x42 + field].try_into().unwrap());
        put(&mut bytes, 0x40 + field, value + 32);
    }
    put(&mut bytes, 0x64, 0x50);
    let mut dialog = 0x4000_0000_u32.to_le_bytes().to_vec();
    dialog.push(1);
    for value in [0_u16, 0, 40, 40] {
        dialog.extend_from_slice(&value.to_le_bytes());
    }
    dialog.extend_from_slice(&[0; 3]); // No menu, system dialog class, no caption.
    for value in [0_u16, 0, 16, 16, 77] {
        dialog.extend_from_slice(&value.to_le_bytes());
    }
    dialog.extend_from_slice(&0x4000_0000_u32.to_le_bytes());
    dialog.extend_from_slice(b"C16DlgParent\0\0\0"); // Registered custom control, no title/data.
    let offset = bytes.len();
    put(&mut bytes, 0x92, 0x8005);
    put(&mut bytes, 0x94, 1);
    put(&mut bytes, 0x9a, offset as u16);
    put(&mut bytes, 0x9c, dialog.len() as u16);
    put(&mut bytes, 0x9e, 0x30);
    put(&mut bytes, 0xa0, 0x800b);
    bytes.extend_from_slice(&dialog);
    bytes
}
