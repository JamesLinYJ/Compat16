//! Actual DOS version calls, including live PSP writes and protected entries.
use super::{Code, ne};

fn compare_register(code: &mut Code, mod_rm: u8, expected: u16) {
    code.emit(&[0x81, mod_rm]);
    code.word(expected);
    code.fail_if(0x85);
}

fn version_call(code: &mut Code, selector: u8, expected: u16, thunk: bool) {
    code.immediate(0xb8, 0x3000 | u16::from(selector));
    code.immediate(0xbb, 0xabcd);
    code.immediate(0xb9, 0x1234);
    if thunk {
        code.call(102);
    } else {
        code.emit(&[0xcd, 0x21]);
    }
    compare_register(code, 0xf8, expected);
    compare_register(code, 0xfb, if selector == 1 { 0 } else { 0xff00 });
    compare_register(code, 0xf9, 0);
}

fn true_version(code: &mut Code, thunk: bool) {
    code.immediate(0xb8, 0x3306);
    if thunk {
        code.call(102);
    } else {
        code.emit(&[0xcd, 0x21]);
    }
    compare_register(code, 0xfb, 0x3205);
    compare_register(code, 0xfa, 0);
}

pub fn dos_version_com(initial: u16) -> Vec<u8> {
    let mut code = Code::default();
    version_call(&mut code, 0, initial, false);
    for version in [0x1606_u16, 0, 0xffff, 0x0007] {
        code.emit(&[0xc7, 0x06, 0x40, 0]); // MOV WORD PTR DS:[PSP:40h],version.
        code.word(version);
        version_call(&mut code, 0, version, false);
        version_call(&mut code, 1, version, false);
        version_call(&mut code, 0x42, version, false);
        true_version(&mut code, false);
    }
    code.finish().bytes
}

pub fn dos_version_program(expected: u16) -> Vec<u8> {
    let mut code = Code::default();
    for thunk in [false, true] {
        version_call(&mut code, 0, expected, thunk);
        version_call(&mut code, 1, expected, thunk);
        true_version(&mut code, thunk);
    }
    let mut data = vec![0; 512];
    data[0x40..0x42].copy_from_slice(&0xbeef_u16.to_le_bytes());
    // DS is an unrelated protected selector. DOS reads its own PSP metadata.
    ne("DOSVERS", &code.finish(), &data, &["KERNEL"], false)
}
