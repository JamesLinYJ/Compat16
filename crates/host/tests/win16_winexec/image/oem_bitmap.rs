//! OEM numeric names and same-numbered guest resources occupy distinct scopes.

use super::{Code, ne, put};

fn call(code: &mut Code, module: u16, ordinal: u16) {
    code.call(ordinal);
    code.imports.last_mut().unwrap().1 = module;
}

fn color(code: &mut Code, value: u32) {
    code.immediate(0x3d, value as u16);
    code.fail_if(0x85);
    code.emit(&[0x81, 0xfa]);
    code.word((value >> 16) as u16);
    code.fail_if(0x85);
}

fn resource_pixels(code: &mut Code) {
    code.immediate(0x68, 0);
    call(code, 3, 52); // CreateCompatibleDC(NULL).
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.immediate(0xa3, 2);
    code.emit(&[0x50, 0xff, 0x36, 0, 0]);
    call(code, 3, 45);
    code.immediate(0xa3, 4); // Save the native DC's original bitmap token.
    for (x, y, expected) in [(0, 0, 0x00ffffff), (1, 0, 0), (0, 1, 0), (1, 1, 0x00ffffff)] {
        code.emit(&[0xff, 0x36, 2, 0]);
        code.immediate(0x68, x);
        code.immediate(0x68, y);
        call(code, 3, 83);
        color(code, expected);
    }
    code.emit(&[0xff, 0x36, 2, 0]);
    for value in [1, 0, 0, 0xff] {
        code.immediate(0x68, value);
    }
    call(code, 3, 31);
    color(code, 0xff);
    code.emit(&[0xff, 0x36, 2, 0]);
    code.immediate(0x68, 1);
    code.immediate(0x68, 0);
    call(code, 3, 83);
    color(code, 0xff);
    code.emit(&[0xff, 0x36, 2, 0, 0xff, 0x36, 4, 0]);
    call(code, 3, 45);
    code.emit(&[0xff, 0x36, 2, 0]);
    call(code, 3, 68);
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    // BITMAP16 reports the actual device stride. Request its exact extent;
    // the native bits pointer remains hidden from the guest.
    for offset in [42, 44] {
        code.emit(&[0x81, 0x3e]);
        code.word(offset);
        code.word(0);
        code.fail_if(0x85);
    }
    code.immediate(0xa1, 38);
    code.emit(&[0xf7, 0x26, 36, 0]);
    code.immediate(0xa3, 6);
    code.emit(&[0xff, 0x36, 0, 0]);
    code.immediate(0x68, 0);
    code.emit(&[0xff, 0x36, 6, 0, 0x1e]);
    code.immediate(0x68, 256);
    call(code, 3, 74);
    code.emit(&[0x3b, 0x06, 6, 0]);
    code.fail_if(0x85);
    code.emit(&[0x81, 0xfa, 0, 0]);
    code.fail_if(0x85);
    for offset in [340, 341] {
        code.emit(&[0x80, 0x3e]);
        code.word(offset);
        code.emit(&[0xa5]);
        code.fail_if(0x85);
    }
}

fn query_and_delete(code: &mut Code, dimensions: Option<(u16, u16)>) {
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84); // A real bitmap must have been created.
    code.immediate(0xa3, 0);
    code.emit(&[0x50]);
    code.immediate(0x68, 14); // sizeof(BITMAP16), not the host BITMAP.
    code.emit(&[0x1e]);
    code.immediate(0x68, 32);
    call(code, 3, 82); // GDI.GetObject.
    code.immediate(0x3d, 14);
    code.fail_if(0x85);
    for (offset, expected) in [(34, dimensions.map(|v| v.0)), (36, dimensions.map(|v| v.1))] {
        code.emit(&[0x81, 0x3e]);
        code.word(offset);
        code.word(expected.unwrap_or(0));
        code.fail_if(if expected.is_some() { 0x85 } else { 0x8e });
    }
    if dimensions.is_some() {
        resource_pixels(code);
    }
    code.emit(&[0xff, 0x36, 0, 0]);
    call(code, 3, 69); // GDI.DeleteObject.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.emit(&[0xff, 0x36, 0, 0]);
    call(code, 3, 69);
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x85); // A deleted guest handle remains invalid.
}

pub fn oem_bitmap_program() -> Vec<u8> {
    let mut code = Code::default();
    for id in [32767, 32765, 32764, 32763, 32762, 32757, 32756, 32755] {
        code.immediate(0x68, 0); // NULL HINSTANCE selects the OEM namespace.
        code.immediate(0x68, 0);
        code.immediate(0x68, id);
        call(&mut code, 2, 175); // USER.LoadBitmap.
        query_and_delete(&mut code, None);
    }
    code.immediate(0x68, 0);
    code.immediate(0x68, 0);
    code.call(47); // KERNEL.GetModuleHandle(NULL).
    code.emit(&[0x50]); // This guest module owns a different RT_BITMAP 32762.
    code.immediate(0x68, 0);
    code.immediate(0x68, 32762);
    call(&mut code, 2, 175);
    query_and_delete(&mut code, Some((7, 3)));
    for id in [0, 0x1234] {
        for value in [0, 0, id] {
            code.immediate(0x68, value);
        }
        call(&mut code, 2, 175);
        code.emit(&[0x0b, 0xc0]);
        code.fail_if(0x85);
    }
    let mut data = [0; 512];
    data[256..342].fill(0xa5);
    let mut bytes = ne(
        "OEMBMP",
        &code.finish(),
        &data,
        &["KERNEL", "USER", "GDI"],
        false,
    );

    // Reserve the resource directory before resident/import/entry tables;
    // segment offsets and ordinal relocation records remain unchanged.
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
    let payload_offset = bytes.len();
    let mut dib = vec![0_u8; 60];
    dib[0..4].copy_from_slice(&40_u32.to_le_bytes());
    dib[4..8].copy_from_slice(&7_i32.to_le_bytes());
    dib[8..12].copy_from_slice(&3_i32.to_le_bytes());
    put(&mut dib, 12, 1);
    put(&mut dib, 14, 1);
    dib[20..24].copy_from_slice(&12_u32.to_le_bytes());
    dib[32..36].copy_from_slice(&2_u32.to_le_bytes());
    dib[44..47].fill(0xff); // Black/white RGBQUAD table.
    for (offset, value) in [(48, 0xaa), (52, 0x54), (56, 0xaa)] {
        dib[offset] = value;
    }
    put(&mut bytes, 0x92, 0x8002);
    put(&mut bytes, 0x94, 1);
    put(&mut bytes, 0x9a, payload_offset as u16);
    put(&mut bytes, 0x9c, dib.len() as u16);
    put(&mut bytes, 0x9e, 0x30);
    put(&mut bytes, 0xa0, 0x8000 | 32762);
    bytes.extend_from_slice(&dib);
    bytes
}
