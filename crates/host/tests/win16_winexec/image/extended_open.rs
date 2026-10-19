//! Guest results for the independent DX code-page flag and action byte.
use super::{Code, ne};

pub fn extended_open_filename(prc: bool) -> &'static [u8] {
    if prc { b"\x81\x5cz.dat" } else { b"\x81z.dat" }
}

fn compare(code: &mut Code, register: u8, value: u16) {
    code.emit(&[0x81, 0xf8 + register]);
    code.word(value);
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

fn open(code: &mut Code, path: u16, action: u16, mode: u16, result: Result<u16, u16>, gate: bool) {
    code.immediate(0xbe, path);
    code.immediate(0xba, action);
    code.immediate(0xbb, mode);
    code.immediate(0xb9, if action & 0xff == 1 { 0xffff } else { 0 });
    invoke(code, 0x6c00, gate, result.is_err());
    compare(code, 2, action); // DX is an action, never a filename pointer.
    compare(code, 6, path);
    match result {
        Ok(outcome) => {
            compare(code, 1, outcome);
            code.emit(&[0x89, 0xc3]); // BX=returned handle.
        }
        Err(error) => compare(code, 0, error),
    }
}

fn read(code: &mut Code, base: u16) {
    code.immediate(0xba, base + 0x240);
    code.immediate(0xb9, 7);
    invoke(code, 0x3f00, false, false);
    compare(code, 0, 7);
    code.immediate(0xbe, base + 0x200);
    code.immediate(0xbf, base + 0x240);
    code.immediate(0xb9, 7);
    code.emit(&[0xfc, 0xf3, 0xa6]);
    code.fail_if(0x85);
    invoke(code, 0x3e00, false, false);
}

pub fn extended_open_program(protected: bool, prc: bool) -> Vec<u8> {
    let base = if protected { 0 } else { 0x3000 };
    let mut data = vec![0; 0x400];
    let name = extended_open_filename(prc);
    data[0x100..0x100 + name.len()].copy_from_slice(name);
    data[0x140..0x148].copy_from_slice(b"NEW.DAT\0");
    data[0x180..0x18c].copy_from_slice(b"MISSING.DAT\0");
    data[0x200..0x207].copy_from_slice(b"open-ok");
    let mut code = Code::default();
    code.emit(&[0x1e, 0x07]); // ES=DS for bounded byte comparison.
    for gate in [false, true]
        .into_iter()
        .take(if protected { 2 } else { 1 })
    {
        for action in [1, 0x101] {
            open(&mut code, base + 0x100, action, 0, Ok(1), gate);
            read(&mut code, base);
        }
        open(&mut code, base + 0x140, 0x110, 2, Ok(2), gate);
        code.immediate(0xba, base + 0x200);
        code.immediate(0xb9, 7);
        invoke(&mut code, 0x4000, false, false);
        compare(&mut code, 0, 7);
        invoke(&mut code, 0x3e00, false, false);
        open(&mut code, base + 0x140, 0x110, 2, Err(80), gate);
        open(&mut code, base + 0x140, 0x201, 2, Err(1), gate);
        open(&mut code, base + 0x140, 0x111, 0, Ok(1), gate);
        read(&mut code, base); // Neither failed request may truncate NEW.DAT.
        open(&mut code, base + 0x180, 0x101, 0, Err(2), gate);
        code.immediate(0xba, base + 0x140);
        invoke(&mut code, 0x4100, false, false);
    }
    let code = code.finish();
    if protected {
        ne("EXTOPEN", &code, &data, &["KERNEL"], false)
    } else {
        let mut bytes = code.bytes;
        assert!(bytes.len() <= usize::from(base - 0x100));
        bytes.resize(usize::from(base - 0x100), 0);
        bytes.extend_from_slice(&data);
        bytes
    }
}
