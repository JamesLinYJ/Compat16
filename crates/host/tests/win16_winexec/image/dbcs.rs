//! Read the actual returned table through real segments or protected aliases.
use super::{Code, ne};

fn compare(code: &mut Code, register: u8, expected: u16) {
    code.emit(&[0x81, 0xf8 + register]);
    code.word(expected);
    code.fail_if(0x85);
}

fn common(dbcs: bool, protected: bool, storage: u16) -> Code {
    let mut code = Code::default();
    // ES retains the data segment while DOS returns a different DS.
    code.emit(&[0x1e, 0x07]);
    for pass in 0..2 {
        code.emit(&[0x1e]);
        for (opcode, value) in [
            (0xbb, 0x2345),
            (0xb9, 0x3456),
            (0xba, 0x4567),
            (0xbf, 0x5678),
            (0xbd, 0x6789),
        ] {
            code.immediate(opcode, value);
        }
        code.emit(&[0x66, 0xbe, 0x21, 0x43, 0x54, 0x76]); // ESI=76544321
        code.immediate(0xb8, 0x6300);
        code.emit(&[0xf9]);
        if protected && pass == 1 {
            code.call(102); // KERNEL DOS3Call must publish DS as well as SI.
        } else {
            code.emit(&[0xcd, 0x21]);
        }
        code.fail_if(0x82);
        compare(&mut code, 0, 0x6300);
        for (register, value) in [
            (3, 0x2345),
            (1, 0x3456),
            (2, 0x4567),
            (7, 0x5678),
            (5, 0x6789),
        ] {
            compare(&mut code, register, value);
        }
        code.emit(&[0x8c, 0xd8]); // AX=DS
        code.immediate(0x3d, 0);
        code.fail_if(0x84);
        code.immediate(0x3d, 0xf000);
        code.fail_if(if protected { 0x84 } else { 0x85 });
        if pass == 0 {
            code.emit(&[0x26, 0xa3]);
            code.word(storage);
            code.emit(&[0x26, 0x89, 0x36]);
            code.word(storage + 2);
        } else {
            code.emit(&[0x26, 0x3b, 0x06]);
            code.word(storage);
            code.fail_if(0x85);
            code.emit(&[0x26, 0x3b, 0x36]);
            code.word(storage + 2);
            code.fail_if(0x85);
        }
        code.emit(&[0x8b, 0x04]); // AX=[DS:SI], not a host-supplied assertion.
        compare(&mut code, 0, if dbcs { 0xfe81 } else { 0 });
        if dbcs {
            code.emit(&[0x8b, 0x44, 0x02]);
            compare(&mut code, 0, 0);
        }
        code.emit(&[0x66, 0x8b, 0xc6, 0x66, 0xc1, 0xe8, 0x10]);
        compare(&mut code, 0, 0x7654);
        code.emit(&[0x1f]);
    }
    code.finish()
}

pub fn dbcs_com(dbcs: bool) -> Vec<u8> {
    let mut bytes = common(dbcs, false, 0x2100).bytes;
    assert!(bytes.len() < 0x2000);
    bytes.resize(0x2004, 0xa5);
    bytes
}

pub fn dbcs_program(dbcs: bool) -> Vec<u8> {
    ne(
        "DBCSTAB",
        &common(dbcs, true, 0),
        &[0xa5; 32],
        &["KERNEL"],
        false,
    )
}
