//! Real DOS errors and a Win16 HFILE failure feed the same AH=59 state.
use super::{Code, ne};

fn compare(code: &mut Code, register: u8, expected: u16) {
    code.emit(&[0x81, 0xf8 + register]);
    code.word(expected);
    code.fail_if(0x85);
}
fn dos_call(code: &mut Code, ax: u16, protected_gate: bool) {
    code.immediate(0xb8, ax);
    if protected_gate {
        code.call(102);
    } else {
        code.emit(&[0xcd, 0x21]);
    }
}
fn failed(code: &mut Code, ax: u16, expected: u16, gate: bool) {
    dos_call(code, ax, gate);
    code.fail_if(0x83);
    compare(code, 0, expected);
}
fn query(code: &mut Code, error: u16, class_action: u16, locus: u8, gate: bool) {
    code.immediate(0xbb, 0xabcd);
    code.immediate(0xb9, 0xeeee);
    code.immediate(0xba, 0x4567);
    code.immediate(0xbe, 0x5678);
    code.immediate(0xbf, 0x6789);
    code.emit(&[0x1e, 0x07, 0xf9]); // ES=DS; incoming carry is not a new failure.
    dos_call(code, 0x5900, gate);
    code.fail_if(0x82);
    compare(code, 0, error);
    compare(code, 3, class_action);
    compare(code, 1, (u16::from(locus) << 8) | 0xee);
    compare(code, 2, 0x4567);
    compare(code, 6, 0x5678);
    compare(code, 7, 0);
    code.emit(&[0x8c, 0xc0]);
    compare(code, 0, 0);
}
fn common(code: &mut Code, data: u16, protected: bool) {
    dos_call(code, 0x5900, false);
    code.fail_if(0x82);
    compare(code, 0, 0);
    code.immediate(0xbb, 0xffff);
    failed(code, 0x3e00, 6, false);
    query(code, 6, 0x0704, 1, false);
    if protected {
        query(code, 6, 0x0704, 1, true);
    }
    code.emit(&[0xf9]);
    dos_call(code, 0x3000, false);
    code.fail_if(0x83);
    compare(code, 0, 5);
    query(code, 6, 0x0704, 1, protected);
    // An unsupported EXEC subfunction fails before consulting its pointers.
    failed(code, 0x4b01, 1, protected);
    query(code, 1, 0x0704, 1, false);
    code.immediate(0xba, data);
    failed(code, 0x3b00, 3, protected);
    query(code, 3, 0x0803, 2, false);
    // Find this very executable, then exhaust its single-name search.
    code.immediate(0xba, data + 0x100);
    dos_call(code, 0x1a00, false);
    code.immediate(0xba, data + 0x40);
    code.immediate(0xb9, 0);
    dos_call(code, 0x4e00, protected);
    code.fail_if(0x82);
    failed(code, 0x4f00, 18, false);
    query(code, 18, 0x0803, 2, protected);
    query(code, 18, 0x0803, 2, false);
}
fn data(name: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xa5; 0x400];
    bytes[..12].copy_from_slice(b"NOEXIST.C16\0");
    bytes[0x40..0x40 + name.len()].copy_from_slice(name);
    bytes[0x80..0x89].copy_from_slice(b"DATA.DAT\0");
    bytes
}
pub fn extended_error_com() -> Vec<u8> {
    let mut code = Code::default();
    common(&mut code, 0x2100, false);
    let mut bytes = code.finish().bytes;
    assert!(bytes.len() < 0x2000);
    bytes.resize(0x2000, 0);
    bytes.extend(data(b"ERRSTATE.COM\0"));
    bytes
}
pub fn extended_error_program() -> Vec<u8> {
    let mut code = Code::default();
    common(&mut code, 0, true);
    // Obtain an actual Win16 HFILE, then reject a DOS write to its read-only
    // host open. This must record the adapter failure rather than a DOS JFT
    // failure for a numerically equal handle. The test also checks the data.
    code.emit(&[0x1e]);
    code.immediate(0x68, 0x80);
    code.immediate(0x68, 0);
    code.call(85);
    code.immediate(0x3d, 0xffff);
    code.fail_if(0x84);
    code.immediate(0xa3, 0x3f0);
    code.emit(&[0x8b, 0xd8]);
    code.immediate(0xb9, 1);
    code.immediate(0xba, 0x380);
    failed(&mut code, 0x4000, 5, true);
    query(&mut code, 5, 0x0303, 1, false);
    code.emit(&[0x8b, 0x1e]);
    code.word(0x3f0);
    failed(&mut code, 0x5702, 1, false);
    query(&mut code, 1, 0x0704, 1, true);
    code.emit(&[0xff, 0x36]);
    code.word(0x3f0);
    code.call(81);
    compare(&mut code, 0, 0);
    ne(
        "ERRSTATE",
        &code.finish(),
        &data(b"ERRSTATE.EXE\0"),
        &["KERNEL"],
        false,
    )
}
