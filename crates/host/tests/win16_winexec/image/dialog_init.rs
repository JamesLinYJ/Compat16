//! A hidden private-class dialog forwards initialization through DefDlgProc.
use super::{Code, ne, put};

fn user(code: &mut Code, ordinal: u16) {
    code.call(ordinal);
    code.imports.last_mut().unwrap().1 = 2;
}

fn compare_memory(code: &mut Code, offset: u16, value: u16) {
    code.emit(&[0x81, 0x3e]);
    code.word(offset);
    code.word(value);
    code.fail_if(0x85);
}

pub fn private_dialog_init_program(handled: bool) -> Vec<u8> {
    let mut code = Code::default();
    for _ in 0..2 {
        code.immediate(0x68, 0);
    }
    code.call(47); // KERNEL.GetModuleHandle(NULL).
    code.immediate(0xa3, 10);
    code.emit(&[0x8c, 0x0e, 4, 0]); // WNDCLASS16.lpfnWndProc selector.
    code.emit(&[0x8c, 0x1e, 24, 0]); // WNDCLASS16.lpszClassName selector.
    code.emit(&[0x1e]);
    code.immediate(0x68, 0);
    user(&mut code, 57);
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.emit(&[0xff, 0x36, 10, 0]);
    for value in [0, 11, 0] {
        code.immediate(0x68, value);
    }
    code.emit(&[0x0e, 0x68]);
    let dialog_site = code.bytes.len();
    code.word(0);
    for value in [0x1357, 0x2468] {
        code.immediate(0x68, value);
    }
    user(&mut code, 241); // CreateDialogParam.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.emit(&[0x3b, 0x06, 0x22, 0]);
    code.fail_if(0x85);
    compare_memory(&mut code, 0x24, u16::from(!handled));
    compare_memory(&mut code, 0x26, if handled { 0 } else { 77 });
    code.emit(&[0x50]);
    user(&mut code, 53); // DestroyWindow; the dialog was never shown.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.interrupt(0x4c00);

    let window_proc = code.bytes.len() as u16;
    code.emit(&[0x55, 0x8b, 0xec]);
    if handled {
        code.emit(&[0x81, 0x7e, 12, 0x10, 1, 0x75, 16]);
        code.emit(&[0x8b, 0x46, 14]);
        code.immediate(0xa3, 0x22);
        code.immediate(0xb8, 0x1234);
        code.immediate(0xba, 0x5678);
        code.emit(&[0x5d, 0xca, 10, 0]);
    }
    for offset in [14, 12, 10, 8, 6] {
        code.emit(&[0xff, 0x76, offset]);
    }
    user(&mut code, 308); // The explicit WndProc -> DefDlgProc -> DLGPROC path.
    code.emit(&[0x5d, 0xca, 10, 0]);

    let dialog_proc = code.bytes.len() as u16;
    code.bytes[dialog_site..dialog_site + 2].copy_from_slice(&dialog_proc.to_le_bytes());
    code.emit(&[0x55, 0x8b, 0xec, 0x81, 0x7e, 12, 0x10, 1, 0x0f, 0x85]);
    let other_message = code.bytes.len();
    code.word(0);
    for (offset, value) in [(6, 0x2468_u16), (8, 0x1357)] {
        code.emit(&[0x81, 0x7e, offset]);
        code.word(value);
        code.fail_if(0x85);
    }
    code.emit(&[0x8b, 0x46, 14]);
    code.immediate(0xa3, 0x22);
    code.emit(&[0xff, 0x06, 0x24, 0, 0xff, 0x76, 14]);
    code.immediate(0x68, 77);
    user(&mut code, 91); // A nested native USER operation during initialization.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.emit(&[0x50]);
    user(&mut code, 277);
    code.immediate(0xa3, 0x26);
    let relative = i16::try_from(code.bytes.len() as isize - (other_message + 2) as isize).unwrap();
    code.bytes[other_message..other_message + 2].copy_from_slice(&relative.to_le_bytes());
    code.emit(&[0x33, 0xc0, 0x33, 0xd2, 0x5d, 0xca, 10, 0]);

    let mut data = vec![0_u8; 512];
    put(&mut data, 2, window_proc);
    put(&mut data, 8, 30); // Win16 DLGWINDOWEXTRA, independent of native storage.
    put(&mut data, 22, 0x100);
    data[0x100..0x10e].copy_from_slice(b"C16PrivateDlg\0");
    let mut bytes = ne("DLGINIT", &code.finish(), &data, &["KERNEL", "USER"], false);
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
    let mut dialog = 0x8000_0000_u32.to_le_bytes().to_vec();
    dialog.push(1);
    for value in [0_u16, 0, 80, 80] {
        dialog.extend_from_slice(&value.to_le_bytes());
    }
    dialog.push(0); // No menu.
    dialog.extend_from_slice(b"C16PrivateDlg\0\0");
    for value in [0_u16, 0, 16, 16, 77] {
        dialog.extend_from_slice(&value.to_le_bytes());
    }
    dialog.extend_from_slice(&0x4000_0000_u32.to_le_bytes());
    dialog.extend_from_slice(&[0x82, 0, 0]); // Hidden STATIC, no title/data.
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
