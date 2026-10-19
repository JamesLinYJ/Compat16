//! Classic FCB enumeration, copied cursors, changed DTA, and EOF in guest code.
use super::{Code, ne};

pub fn fcb_search_filename(prc: bool, letter: u8) -> Vec<u8> {
    let mut name = if prc { vec![0x81, 0x5c] } else { vec![0x81] };
    name.push(letter);
    name.extend_from_slice(b".TXT");
    name
}

fn compare(code: &mut Code, register: u8, value: u16) {
    code.emit(&[0x81, 0xf8 + register]);
    code.word(value);
    code.fail_if(0x85);
}

fn byte(code: &mut Code, address: u16, expected: u8) {
    code.emit(&[0x80, 0x3e]);
    code.word(address);
    code.emit(&[expected]);
    code.fail_if(0x85);
}

fn word(code: &mut Code, address: u16, expected: u16) {
    code.emit(&[0x81, 0x3e]);
    code.word(address);
    code.word(expected);
    code.fail_if(0x85);
}

fn copy(code: &mut Code, source: u16, destination: u16, count: u16) {
    code.immediate(0xbe, source);
    code.immediate(0xbf, destination);
    code.immediate(0xb9, count);
    code.emit(&[0xfc, 0xf3, 0xa4]);
}

fn equal(code: &mut Code, left: u16, right: u16, count: u16) {
    code.immediate(0xbe, left);
    code.immediate(0xbf, right);
    code.immediate(0xb9, count);
    code.emit(&[0xfc, 0xf3, 0xa6]);
    code.fail_if(0x85);
}

fn dta(code: &mut Code, address: u16) {
    code.immediate(0xba, address);
    code.interrupt(0x1a00);
}

fn stage(code: &mut Code, base: u16, value: u8) {
    code.emit(&[0xc6, 0x06]);
    code.word(base + 0x604);
    code.emit(&[value]);
}

fn search(code: &mut Code, address: u16, first: bool, status: u8, carry: bool, gate: bool) {
    code.immediate(0xba, address);
    code.immediate(0xbb, 0x2345);
    code.immediate(0xb9, 0x3456);
    code.immediate(0xbe, 0x4567);
    code.immediate(0xbf, 0x5678);
    code.immediate(0xb8, if first { 0x1107 } else { 0x1207 });
    code.emit(&[if carry { 0xf9 } else { 0xf8 }]);
    if gate {
        code.call(102);
    } else {
        code.emit(&[0xcd, 0x21]);
    }
    code.fail_if(if carry { 0x83 } else { 0x82 }); // Preserve incoming CF.
    code.emit(&[0x3c, status]);
    code.fail_if(0x85);
    compare(code, 3, 0x2345);
    compare(code, 1, 0x3456);
    compare(code, 2, address);
    compare(code, 6, 0x4567);
    compare(code, 7, 0x5678);
}

fn record(code: &mut Code, address: u16, base: u16, prc: bool) {
    code.emit(&[0xa0]);
    code.word(address);
    code.emit(&[0x3a, 0x06]);
    code.word(base + 0x602);
    code.fail_if(0x85);
    let prefix = if prc {
        byte(code, address + 1, 0x81);
        byte(code, address + 2, 0x5c);
        2
    } else {
        byte(code, address + 1, 0x9a);
        1
    };
    code.emit(&[0xa0]);
    code.word(address + 1 + prefix);
    code.emit(&[0x3c, b'A']);
    code.fail_if(0x82);
    code.emit(&[0x3c, b'B']);
    code.fail_if(0x87);
    code.emit(&[0xa2]);
    code.word(base + 0x606);
    code.emit(&[0x2c, b'A', 0xd0, 0xe0, 0x04, 3, 0x30, 0xe4]);
    code.emit(&[0x3b, 0x06]);
    code.word(address + 29);
    code.fail_if(0x85);
    word(code, address + 31, 0);
    word(code, address + 9, 0x5854);
    byte(code, address + 11, b'T');
    word(code, address + 33, 0xa5a5);
    word(code, address + 46, 0xa5a5);
}

pub fn fcb_search_program(protected: bool, prc: bool) -> Vec<u8> {
    let base = if protected { 0 } else { 0x3000 };
    let mut data = vec![0xa5; 0x800];
    let mut input = [0; 37];
    input[1..12].fill(b' ');
    let prefix = if prc { b"\x81\\".as_slice() } else { b"\x81" };
    input[1..1 + prefix.len()].copy_from_slice(prefix);
    input[1 + prefix.len()] = b'?';
    input[9..12].copy_from_slice(b"TXT");
    data[0x100..0x125].copy_from_slice(&input);
    data[0x200..0x225].copy_from_slice(&input);
    data[0x180..0x187].fill(0);
    data[0x180] = 0xff;
    data[0x186] = 8;
    data[0x187..0x1ac].copy_from_slice(&input);
    let mut code = Code::default();
    code.emit(&[0x1e, 0x07]); // ES=DS; all operands stay in owned guest data.
    code.interrupt(0x1900);
    code.emit(&[0xfe, 0xc0, 0xa2]);
    code.word(base + 0x602);
    for gate in [false, true]
        .into_iter()
        .take(if protected { 2 } else { 1 })
    {
        copy(&mut code, base + 0x200, base + 0x100, 22);
        dta(&mut code, base + 0x300);
        stage(&mut code, base, 1);
        search(&mut code, base + 0x100, true, 0, true, gate);
        stage(&mut code, base, 2);
        record(&mut code, base + 0x300, base, prc);
        code.emit(&[0xa0]);
        code.word(base + 0x606);
        code.emit(&[0xa2]);
        code.word(base + 0x600);
        copy(&mut code, base + 0x100, base + 0x140, 22);
        dta(&mut code, base + 0x380);
        stage(&mut code, base, 3);
        search(&mut code, base + 0x100, false, 0, false, gate);
        stage(&mut code, base, 4);
        record(&mut code, base + 0x380, base, prc);
        code.emit(&[0xa0]);
        code.word(base + 0x606);
        code.emit(&[0x3a, 0x06]);
        code.word(base + 0x600);
        code.fail_if(0x84);
        copy(&mut code, base + 0x380, base + 0x540, 33);
        stage(&mut code, base, 5);
        search(&mut code, base + 0x100, false, 0xff, true, gate);
        equal(&mut code, base + 0x380, base + 0x540, 33);
        stage(&mut code, base, 6);
        search(&mut code, base + 0x140, false, 0, false, gate);
        equal(&mut code, base + 0x380, base + 0x540, 33);
        stage(&mut code, base, 7);
        search(&mut code, base + 0x180, true, 0xff, false, gate);
        equal(&mut code, base + 0x380, base + 0x540, 33);
    }
    let mut code = code.finish();
    // Report the failing phase through DOS exit status, retaining all checks.
    code.bytes.truncate(code.bytes.len() - 5);
    code.emit(&[0xa0]);
    code.word(base + 0x604);
    code.emit(&[0xb4, 0x4c, 0xcd, 0x21]);
    if protected {
        ne("FCBFIND", &code, &data, &["KERNEL"], false)
    } else {
        let mut bytes = code.bytes;
        assert!(bytes.len() <= usize::from(base - 0x100));
        bytes.resize(usize::from(base - 0x100), 0);
        bytes.extend_from_slice(&data);
        bytes
    }
}
