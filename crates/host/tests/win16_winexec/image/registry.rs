//! String ownership and Win3.1 errors through SHELL and KERNEL registry APIs.
use super::{Code, ne};

#[path = "registry/expand.rs"]
mod expand;
pub use expand::registry_expand_program;

#[path = "registry/cursor.rs"]
mod cursor;
pub use cursor::registry_cursor_program;

#[path = "registry/query.rs"]
mod query;
pub use query::registry_query_program;
#[path = "registry/buffer.rs"]
mod buffer;
pub use buffer::registry_buffer_program;
#[path = "registry/optional_length.rs"]
mod optional_length;
pub use optional_length::registry_optional_length_program;
#[path = "registry/roots.rs"]
mod roots;
pub use roots::registry_roots_program;
#[path = "registry/aliases.rs"]
mod aliases;
pub use aliases::registry_aliases_program;

const KEY: u16 = 0;
const SIZE: u16 = 4;
const TEXT: u16 = 32;
const EMPTY: u16 = 48;
const OUTPUT: u16 = 64;
const PATH: u16 = 256;

fn long(code: &mut Code, value: u32) {
    code.immediate(0x68, (value >> 16) as u16);
    code.immediate(0x68, value as u16);
}
fn far(code: &mut Code, offset: u16) {
    code.emit(&[0x1e]);
    code.immediate(0x68, offset);
}
fn key(code: &mut Code) {
    key_at(code, KEY);
}
fn key_at(code: &mut Code, key: u16) {
    for offset in [key + 2, key] {
        code.emit(&[0xff, 0x36]);
        code.word(offset);
    }
}
fn call(code: &mut Code, module: u16, ordinal: u16, status: u16) {
    code.call(ordinal);
    code.imports.last_mut().unwrap().1 = module;
    code.immediate(0x3d, status);
    code.fail_if(0x85);
    code.emit(&[0x0b, 0xd2]); // DX:AX is a LONG result.
    code.fail_if(0x85);
}
fn store(code: &mut Code, offset: u16, value: u16) {
    code.emit(&[0xc7, 0x06]);
    code.word(offset);
    code.word(value);
}
fn compare(code: &mut Code, offset: u16, value: u16) {
    code.emit(&[0x81, 0x3e]);
    code.word(offset);
    code.word(value);
    code.fail_if(0x85);
}
fn query(code: &mut Code, module: u16, ordinal: u16, expected: &[u8]) {
    store(code, SIZE, 64);
    store(code, SIZE + 2, 0);
    for offset in 0..=expected.len() as u16 {
        store(code, OUTPUT + offset, 0xcccc);
    }
    key(code);
    long(code, 0);
    far(code, OUTPUT);
    far(code, SIZE);
    call(code, module, ordinal, 0);
    compare(code, SIZE, expected.len() as u16);
    compare(code, SIZE + 2, 0);
    for (offset, byte) in expected.iter().copied().chain([0xcc]).enumerate() {
        code.emit(&[0x80, 0x3e]);
        code.word(OUTPUT + offset as u16);
        code.emit(&[byte]);
        code.fail_if(0x85);
    }
}

pub fn registry_program(path: &str) -> Vec<u8> {
    assert!(
        path.starts_with("Compat16Test.") && path.is_ascii() && !path.contains(['\\', '/', '\0'])
    );
    let mut data = vec![0_u8; 512];
    data[TEXT as usize..TEXT as usize + 7].copy_from_slice(b"Test\xd6\xd0\0");
    data[EMPTY as usize + 1] = b'0';
    for (offset, text) in [
        (80, b"protocol\\StdFileEditing\0".as_slice()),
        (112, b"server\0".as_slice()),
        (128, b"protocol\\StdFileEditing\\server\0".as_slice()),
        (176, b"protocol\0".as_slice()),
    ] {
        data[offset..offset + text.len()].copy_from_slice(text);
    }
    data[PATH as usize..PATH as usize + path.len()].copy_from_slice(path.as_bytes());
    let mut code = Code::default();
    // Shared string transfer, distinct Win3.1 and KERNEL Win32 thunk semantics.
    for (module, create, set, get, close, delete, enumerate) in
        [(2, 2, 5, 6, 3, 4, 7), (1, 218, 221, 224, 220, 219, 216)]
    {
        let win31 = module == 2;
        long(&mut code, 0x8000_0001);
        far(&mut code, PATH);
        far(&mut code, KEY);
        call(&mut code, module, create, 0);
        // Opening an existing parent yields an independently owned alias.
        long(&mut code, 0x8000_0001);
        far(&mut code, PATH);
        far(&mut code, 12);
        call(&mut code, module, create, 0);
        key_at(&mut code, 12);
        call(&mut code, module, close, 0);
        // Reproduce the OLE registration shape using only the fixture's key.
        key(&mut code);
        far(&mut code, 80);
        far(&mut code, 12);
        call(&mut code, module, create, 0);
        key_at(&mut code, 12);
        far(&mut code, 112);
        long(&mut code, 1);
        far(&mut code, TEXT);
        long(&mut code, 0);
        call(&mut code, module, set, 0);
        key_at(&mut code, 12);
        call(&mut code, module, close, 0);
        for offset in [128, 80, 176] {
            key(&mut code);
            far(&mut code, offset);
            call(&mut code, module, delete, 0);
        }
        for count in [0, 1, u32::MAX] {
            key(&mut code);
            long(&mut code, 0);
            long(&mut code, 1);
            far(&mut code, TEXT);
            long(&mut code, count);
            call(&mut code, module, set, 0);
            query(&mut code, module, get, b"Test\xd6\xd0\0");
        }
        key(&mut code);
        long(&mut code, 0);
        long(&mut code, 1);
        far(&mut code, EMPTY);
        long(&mut code, 0);
        call(&mut code, module, set, 0);
        query(&mut code, module, get, b"\0");
        key(&mut code);
        long(&mut code, 0);
        long(&mut code, 1);
        long(&mut code, 0);
        long(&mut code, u32::MAX);
        call(&mut code, module, set, if win31 { 0 } else { 87 });
        query(&mut code, module, get, if win31 { b"0\0" } else { b"\0" });
        // Establish the same value after exercising the distinct NULL cases.
        key(&mut code);
        long(&mut code, 0);
        long(&mut code, 1);
        far(&mut code, EMPTY + 1);
        long(&mut code, 0);
        call(&mut code, module, set, 0);
        // Unsupported types leave data intact and return API-specific errors.
        key(&mut code);
        long(&mut code, 0xffff_0001);
        long(&mut code, 4);
        long(&mut code, 0xffff_0001);
        long(&mut code, u32::MAX);
        call(&mut code, module, set, if win31 { 7 } else { 87 });
        query(&mut code, module, get, b"0\0");
        // Win3.1 truncates; KERNEL's Win32 thunk reports MORE_DATA.
        store(&mut code, SIZE, 1);
        store(&mut code, OUTPUT, 0xcccc);
        key(&mut code);
        long(&mut code, 0);
        far(&mut code, OUTPUT);
        far(&mut code, SIZE);
        call(&mut code, module, get, if win31 { 0 } else { 234 });
        compare(&mut code, SIZE, if win31 { 1 } else { 2 });
        compare(&mut code, OUTPUT, if win31 { 0xcc30 } else { 0xcccc });
        key(&mut code);
        long(&mut code, 0);
        far(&mut code, OUTPUT);
        long(&mut code, 64);
        call(&mut code, module, enumerate, if win31 { 2 } else { 259 });
        for status in [0, if win31 { 8 } else { 6 }] {
            key(&mut code);
            call(&mut code, module, close, status);
        }
        for status in [0, 2] {
            long(&mut code, 0x8000_0001);
            far(&mut code, PATH);
            call(&mut code, module, delete, status);
        }
    }
    ne(
        "REGTEXT",
        &code.finish(),
        &data,
        &["KERNEL", "SHELL"],
        false,
    )
}
