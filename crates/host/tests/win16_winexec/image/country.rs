//! Country records, actual guest callbacks, byte tables and DBCS filenames.
use super::{Code, ne};

fn compare(code: &mut Code, register: u8, value: u16) {
    code.emit(&[0x81, 0xf8 + register]);
    code.word(value);
    code.fail_if(0x85);
}
fn store(code: &mut Code, offset: u16, value: u16) {
    code.emit(&[0xc7, 0x06]);
    code.word(offset);
    code.word(value);
}
fn word(code: &mut Code, offset: u16, value: u16) {
    code.emit(&[0x81, 0x3e]);
    code.word(offset);
    code.word(value);
    code.fail_if(0x85);
}
fn byte(code: &mut Code, offset: u16, value: u8) {
    code.emit(&[0x80, 0x3e]);
    code.word(offset);
    code.emit(&[value]);
    code.fail_if(0x85);
}
fn invoke(code: &mut Code, ax: u16, gate: bool, error: bool) {
    code.immediate(0xb8, ax);
    code.emit(&[0xf9]);
    if gate {
        code.call(102);
    } else {
        code.emit(&[0xcd, 0x21]);
    }
    code.fail_if(if error { 0x83 } else { 0x82 });
}
fn callback(code: &mut Code, pointer: u16, input: u8, output: u8) {
    code.immediate(0xbb, 0x2345);
    code.immediate(0xb8, 0x5a00 | u16::from(input));
    code.emit(&[0xf9, 0xff, 0x1e]);
    code.word(pointer);
    code.fail_if(0x83); // The callback preserves incoming FLAGS, including CF.
    compare(code, 0, 0x5a00 | u16::from(output));
    compare(code, 3, 0x2345);
}
fn buffer(code: &mut Code, offset: u16, length: u16) {
    for index in (0..length).step_by(2) {
        store(code, offset + index, 0xcccc);
    }
}

pub fn country_filename(prc: bool) -> &'static [u8] {
    if prc { b"\x81\x61z.dat" } else { b"az.dat" }
}

fn data(prc: bool) -> Vec<u8> {
    let mut data = vec![0; 0x300];
    let name = country_filename(prc);
    data[0x220..0x220 + name.len()].copy_from_slice(name);
    data[0x240..0x244].copy_from_slice(b"nls!");
    data
}

fn common(prc: bool, protected: bool, base: u16) -> Code {
    let country = if prc { 86 } else { 1 };
    let page = if prc { 936 } else { 437 };
    let legacy = base + 0x100;
    let extended = base + 0x140;
    let descriptor = base + 0x180;
    let mut code = Code::default();
    code.emit(&[0x1e, 0x07]); // ES=DS for all output buffers.
    for gate in [false, protected] {
        buffer(&mut code, legacy, 32);
        code.immediate(0xba, legacy);
        invoke(&mut code, 0x3800, gate, false);
        compare(&mut code, 0, country);
        compare(&mut code, 3, country);
        word(&mut code, legacy, if prc { 2 } else { 0 });
        word(
            &mut code,
            legacy + 2,
            if prc {
                u16::from(b'\\')
            } else {
                u16::from(b'$')
            },
        );
        word(&mut code, legacy + 16, if prc { 0x0102 } else { 2 });
        for offset in 24..32 {
            byte(&mut code, legacy + offset, 0xcc);
        }
        callback(&mut code, legacy + 18, 0x82, if prc { 0x82 } else { b'E' });
        callback(&mut code, legacy + 18, b'a', b'a');

        buffer(&mut code, extended, 48);
        code.immediate(0xbb, 0xffff);
        code.immediate(0xba, 0xffff);
        code.immediate(0xb9, 48);
        code.immediate(0xbf, extended);
        invoke(&mut code, 0x6501, gate, false);
        compare(&mut code, 0, page);
        compare(&mut code, 1, 41);
        byte(&mut code, extended, 1);
        word(&mut code, extended + 1, 38);
        word(&mut code, extended + 3, country);
        word(&mut code, extended + 5, page);
        word(&mut code, extended + 7, if prc { 2 } else { 0 });
        for offset in 41..48 {
            byte(&mut code, extended + offset, 0xcc);
        }
        for (left, right) in [(legacy + 18, extended + 25), (legacy + 20, extended + 27)] {
            code.immediate(0xa1, left);
            code.emit(&[0x3b, 0x06]);
            code.word(right);
            code.fail_if(0x85);
        }
        callback(
            &mut code,
            extended + 25,
            0x82,
            if prc { 0x82 } else { b'E' },
        );

        for function in [2, 4, 6] {
            buffer(&mut code, descriptor, 8);
            code.immediate(0xbb, 0xffff);
            code.immediate(0xba, 0xffff);
            code.immediate(0xb9, 5);
            code.immediate(0xbf, descriptor);
            invoke(&mut code, 0x6500 | function, gate, false);
            compare(&mut code, 0, page);
            compare(&mut code, 1, 5);
            byte(&mut code, descriptor, function as u8);
            byte(&mut code, descriptor + 5, 0xcc);
            code.emit(&[0x1e, 0xc5, 0x36]);
            code.word(descriptor + 1); // PUSH DS; LDS SI,[descriptor+1]
            code.emit(&[0x8b, 0x04]);
            compare(&mut code, 0, if function == 6 { 256 } else { 128 });
            let offset = if function == 6 {
                0x82 + 2
            } else {
                0x82 - 0x80 + 2
            };
            code.emit(&[0x8a, 0x84]);
            code.word(offset);
            code.emit(&[0x3c, if prc { 0x82 } else { b'E' }]);
            code.fail_if(0x85);
            code.emit(&[0x1f]);
        }
        // A mismatched country/page is rejected even though both individual
        // pages are supported. No output bytes are published on error.
        buffer(&mut code, extended, 48);
        code.immediate(0xbb, page);
        code.immediate(0xba, if prc { 1 } else { 86 });
        code.immediate(0xb9, 41);
        code.immediate(0xbf, extended);
        invoke(&mut code, 0x6501, gate, true);
        compare(&mut code, 0, 2);
        for offset in 0..48 {
            byte(&mut code, extended + offset, 0xcc);
        }
    }
    // Exercise the shared DOS filename normalization with a lowercase-valued
    // DBCS trail byte. The native harness verifies the original Unicode name.
    code.immediate(0xb9, 0);
    code.immediate(0xba, base + 0x220);
    invoke(&mut code, 0x3c00, protected, false);
    code.emit(&[0x8b, 0xd8]);
    code.immediate(0xb9, 4);
    code.immediate(0xba, base + 0x240);
    invoke(&mut code, 0x4000, protected, false);
    compare(&mut code, 0, 4);
    invoke(&mut code, 0x3e00, protected, false);
    code.finish()
}

pub fn country_com(prc: bool) -> Vec<u8> {
    let mut bytes = common(prc, false, 0x2100).bytes;
    assert!(bytes.len() < 0x2000);
    bytes.resize(0x2000, 0);
    bytes.extend(data(prc));
    bytes
}
pub fn country_program(prc: bool) -> Vec<u8> {
    ne(
        "COUNTRY",
        &common(prc, true, 0),
        &data(prc),
        &["KERNEL"],
        false,
    )
}
