//! Guest FCB mutation contracts, actual file contents, and preserved input bytes.
use super::{Code, ne};

fn compare(code: &mut Code, register: u8, value: u16) {
    code.emit(&[0x81, 0xf8 + register]);
    code.word(value);
    code.fail_if(0x85);
}
fn equal(code: &mut Code, left: u16, right: u16, length: u16) {
    code.immediate(0xbe, left);
    code.immediate(0xbf, right);
    code.immediate(0xb9, length);
    code.emit(&[0xfc, 0xf3, 0xa6]);
    code.fail_if(0x85);
}
fn invoke(code: &mut Code, address: u16, ah: u8, status: u8, carry: bool, gate: bool) {
    for (opcode, value) in [
        (0xba, address),
        (0xbb, 0x2345),
        (0xb9, 0x3456),
        (0xbe, 0x4567),
        (0xbf, 0x5678),
        (0xb8, u16::from(ah) << 8 | 7),
    ] {
        code.immediate(opcode, value);
    }
    code.emit(&[if carry { 0xf9 } else { 0xf8 }]);
    if gate {
        code.call(102);
    } else {
        code.emit(&[0xcd, 0x21]);
    }
    code.fail_if(if carry { 0x83 } else { 0x82 });
    compare(code, 0, u16::from(ah) << 8 | u16::from(status));
    for (register, value) in [
        (3, 0x2345),
        (1, 0x3456),
        (2, address),
        (6, 0x4567),
        (7, 0x5678),
    ] {
        compare(code, register, value);
    }
}
fn error(code: &mut Code, expected: u16) {
    code.immediate(0xbb, 0);
    code.interrupt(0x5900);
    code.fail_if(0x82);
    compare(code, 0, expected);
}
fn fcb(
    data: &mut [u8],
    offset: usize,
    old: &[u8; 11],
    new: Option<&[u8; 11]>,
    attributes: Option<u8>,
) {
    let skip = if let Some(attributes) = attributes {
        data[offset..offset + 7].fill(0);
        data[offset] = 0xff;
        data[offset + 6] = attributes;
        7
    } else {
        0
    };
    let start = offset + skip;
    data[start..start + 28].fill(0);
    data[start + 1..start + 12].copy_from_slice(old);
    data[start + 16] = 26; // Reserved byte: it must never select a destination drive.
    if let Some(new) = new {
        data[start + 17..start + 28].copy_from_slice(new);
    }
}
pub fn fcb_mutation_program(protected: bool, prc: bool) -> Vec<u8> {
    let base = if protected { 0 } else { 0x3000 };
    let mut data = vec![0xa5; 0x1000];
    let mut oem = *b"        OLD";
    let prefix = if prc { b"\x81\\".as_slice() } else { b"\x81" };
    oem[..prefix.len()].copy_from_slice(prefix);
    oem[prefix.len()] = b'?';
    fcb(&mut data, 0x100, &oem, Some(b"????????NEW"), None);
    oem[8..].copy_from_slice(b"NEW");
    fcb(&mut data, 0x140, &oem, None, None);
    fcb(&mut data, 0x180, b"DEL2    TMP", None, None);
    fcb(&mut data, 0x1c0, b"DEL?    TMP", None, None);
    fcb(&mut data, 0x200, b"DEL2    TMP", None, Some(1));
    fcb(&mut data, 0x240, b"COLL?   OLD", Some(b"SAME    NEW"), None);
    fcb(&mut data, 0x280, b"SAME    NEW", Some(b"SAME    NEW"), None);
    fcb(
        &mut data,
        0x2c0,
        b"DIROLD     ",
        Some(b"DIRNEW     "),
        Some(0x10),
    );
    fcb(&mut data, 0x300, b"DIRNEW     ", None, Some(0x10));
    fcb(&mut data, 0x340, b"LOCK    TMP", None, None);
    fcb(&mut data, 0x380, b"DEL2    TMP", Some(b"RODONE  TMP"), None);
    fcb(&mut data, 0x3c0, b"RODONE  TMP", Some(b"DEL2    TMP"), None);
    fcb(&mut data, 0x400, b"DIROLD     ", Some(b"DIRNEW     "), None);
    let snapshot = data[0x100..0x440].to_vec();
    data[0xa00..0xd40].copy_from_slice(&snapshot);
    data[0x500..0x504].copy_from_slice(b"INT\0");
    data[0x510..0x515].copy_from_slice(b"GATE\0");
    data[0x520..0x523].copy_from_slice(b"..\0");
    let mut name = prefix.to_vec();
    name.extend_from_slice(b"A.NEW\0");
    data[0x600..0x600 + name.len()].copy_from_slice(&name);
    data[0x620..0x629].copy_from_slice(b"LOCK.TMP\0");
    let mut code = Code::default();
    code.emit(&[0x1e, 0x07]);
    for gate in [false, true]
        .into_iter()
        .take(if protected { 2 } else { 1 })
    {
        code.immediate(0xba, base + if gate { 0x510 } else { 0x500 });
        code.interrupt(0x3b00);
        code.fail_if(0x82);
        code.immediate(0xba, base + 0x700);
        code.interrupt(0x1a00);
        let mut phase = 0u8;
        let mut step = |code: &mut Code| {
            phase += 1;
            code.emit(&[0xc6, 0x06]);
            code.word(base + 0x6f0);
            code.emit(&[phase + if gate { 32 } else { 0 }]);
        };
        step(&mut code);
        invoke(&mut code, base + 0x100, 0x17, 0, true, gate);
        step(&mut code);
        code.immediate(0xba, base + 0x600);
        code.interrupt(0x3d00);
        code.fail_if(0x82);
        code.emit(&[0x89, 0xc3]);
        code.immediate(0xba, base + 0x660);
        code.immediate(0xb9, 3);
        code.interrupt(0x3f00);
        code.fail_if(0x82);
        compare(&mut code, 0, 3);
        code.emit(&[0x81, 0x3e]);
        code.word(base + 0x660);
        code.word(0x6e6f);
        code.fail_if(0x85);
        code.emit(&[0x80, 0x3e]);
        code.word(base + 0x662);
        code.emit(&[b'e']);
        code.fail_if(0x85);
        code.interrupt(0x3e00);
        code.fail_if(0x82);
        step(&mut code);
        invoke(&mut code, base + 0x140, 0x13, 0, false, gate);
        step(&mut code);
        invoke(&mut code, base + 0x380, 0x17, 0, true, gate);
        step(&mut code);
        invoke(&mut code, base + 0x3c0, 0x17, 0, false, gate);
        step(&mut code);
        invoke(&mut code, base + 0x180, 0x13, 0xff, true, gate);
        error(&mut code, 5);
        step(&mut code);
        invoke(&mut code, base + 0x1c0, 0x13, 0, false, gate);
        step(&mut code);
        invoke(&mut code, base + 0x200, 0x13, 0, true, gate);
        step(&mut code);
        invoke(&mut code, base + 0x240, 0x17, 0xff, false, gate);
        error(&mut code, 5);
        step(&mut code);
        invoke(&mut code, base + 0x280, 0x17, 0xff, true, gate);
        error(&mut code, 5);
        step(&mut code);
        invoke(&mut code, base + 0x400, 0x17, 0xff, false, gate);
        error(&mut code, 2);
        step(&mut code);
        invoke(&mut code, base + 0x2c0, 0x17, 0, false, gate);
        step(&mut code);
        invoke(&mut code, base + 0x300, 0x13, 0xff, true, gate);
        error(&mut code, 5);
        step(&mut code);
        code.immediate(0xba, base + 0x620);
        code.interrupt(0x3d00);
        code.fail_if(0x82);
        code.emit(&[0xa3]);
        code.word(base + 0x650);
        invoke(&mut code, base + 0x340, 0x13, 0xff, false, gate);
        error(&mut code, 5);
        code.emit(&[0x8b, 0x1e]);
        code.word(base + 0x650);
        code.interrupt(0x3e00);
        code.fail_if(0x82);
        step(&mut code);
        invoke(&mut code, base + 0x340, 0x13, 0, true, gate);
        step(&mut code);
        code.emit(&[0x1e, 0x07]); // AH=59h returns ES:DI; restore ES=DS for CMPS.
        equal(&mut code, base + 0x100, base + 0xa00, 0x340);
        equal(&mut code, base + 0x700, base + 0x780, 80);
        code.immediate(0xba, base + 0x520);
        code.interrupt(0x3b00);
        code.fail_if(0x82);
    }
    let mut code = code.finish();
    code.bytes.truncate(code.bytes.len() - 5);
    code.emit(&[0xa0]);
    code.word(base + 0x6f0);
    code.emit(&[0xb4, 0x4c, 0xcd, 0x21]);
    if protected {
        ne("FCBMUT", &code, &data, &["KERNEL"], false)
    } else {
        let mut bytes = code.bytes;
        assert!(bytes.len() <= usize::from(base - 0x100));
        bytes.resize(usize::from(base - 0x100), 0);
        bytes.extend(data);
        bytes
    }
}
