//! A real COM caller checks the message-pointer ABI and calls its own provider.
use super::Code;

fn multiplex(code: &mut Code, ax: u16) {
    code.immediate(0xb8, ax);
    code.emit(&[0xcd, 0x2f]);
}

fn compare(code: &mut Code, register: u8, value: u16) {
    code.emit(&[0x81, 0xf8 + register]);
    code.word(value);
    code.fail_if(0x85);
}

fn exchange(code: &mut Code, operation: u8) {
    code.immediate(0xbb, 0x4567);
    code.immediate(0xb9, 0x5678);
    code.immediate(0xba, 0xab00 | u16::from(operation));
    code.immediate(0xbe, 0x789a);
    code.emit(&[0x8b, 0xec, 0xf9]); // BP=SP; carry must be cleared by 122Eh.
    multiplex(code, 0x122e);
    code.fail_if(0x82);
    code.emit(&[0x3b, 0xec]);
    code.fail_if(0x85);
    compare(code, 0, 0x122e);
    compare(code, 3, 0x4567);
    compare(code, 1, 0x5678);
    compare(code, 2, 0xab00 | u16::from(operation));
    compare(code, 6, 0x789a);
}

fn check_address(code: &mut Code, offset: u16, present: bool) {
    compare(code, 7, offset);
    code.emit(&[0x8c, 0xc0]); // AX=ES.
    if present {
        code.emit(&[0x1e, 0x5b, 0x3b, 0xc3]);
    } else {
        code.emit(&[0x0b, 0xc0]);
    }
    code.fail_if(0x85);
}

pub fn dos_message_com() -> Vec<u8> {
    let mut code = Code::default();
    code.emit(&[0xf9]);
    multiplex(&mut code, 0x1200);
    code.fail_if(0x83);
    compare(&mut code, 0, 0x12ff);
    for slot in 0..5u16 {
        exchange(&mut code, (slot * 2) as u8);
        check_address(&mut code, 0, false);
        code.emit(&[0x0e, 0x07]);
        code.immediate(0xbf, 0x1400 + slot * 16);
        exchange(&mut code, (slot * 2 + 1) as u8);
        check_address(&mut code, 0x1400 + slot * 16, true);
    }
    for slot in 0..5u16 {
        code.emit(&[0x0e, 0x07]);
        code.immediate(0xbf, 0xffff);
        exchange(&mut code, (slot * 2) as u8);
        check_address(&mut code, 0x1400 + slot * 16, true);
    }
    // Register a resident-code entry, retrieve it, and call the exact guest FAR
    // pointer. The pointer exchange itself must not execute or inspect it.
    code.emit(&[0x0e, 0x07]);
    code.immediate(0xbf, 0x2010);
    exchange(&mut code, 9);
    exchange(&mut code, 8);
    check_address(&mut code, 0x2010, true);
    code.emit(&[0x89, 0x3e]);
    code.word(0x2000);
    code.emit(&[0x8c, 0xc0, 0xa3]);
    code.word(0x2002);
    code.emit(&[0xff, 0x1e]);
    code.word(0x2000);
    compare(&mut code, 0, 0xbeef);
    for slot in 0..5u16 {
        code.emit(&[0x31, 0xc0, 0x8e, 0xc0]);
        code.immediate(0xbf, 0);
        exchange(&mut code, (slot * 2 + 1) as u8);
        exchange(&mut code, (slot * 2) as u8);
        check_address(&mut code, 0, false);
    }
    let mut bytes = code.finish().bytes;
    assert!(bytes.len() < 0x1f00);
    bytes.resize(0x1f14, 0);
    bytes[0x1f10..0x1f14].copy_from_slice(&[0xb8, 0xef, 0xbe, 0xcb]);
    bytes
}
