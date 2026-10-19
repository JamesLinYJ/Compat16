//! NULL output must size the guest encoding independently of buffer capacity.
use super::{Code, KEY, OUTPUT, PATH, SIZE, TEXT, call, compare, far, key, long, ne, store};

fn size_and_read(code: &mut Code, module: u16, get: u16, expected: &[u8]) {
    for initial in [0, 1, 64, 0x8000_0000, u32::MAX] {
        store(code, SIZE, initial as u16);
        store(code, SIZE + 2, (initial >> 16) as u16);
        store(code, OUTPUT, 0xcccc);
        key(code);
        long(code, 0);
        long(code, 0); // NULL data, not a zero-capacity non-NULL buffer.
        far(code, SIZE);
        call(code, module, get, 0);
        compare(code, SIZE, expected.len() as u16);
        compare(code, SIZE + 2, 0);
        compare(code, OUTPUT, 0xcccc);
    }
    // Reuse the returned size for an exactly sized second call. Keep a guard
    // beyond the last byte; lengths include the guest encoding's terminator.
    store(code, OUTPUT + expected.len() as u16, 0xcccc);
    key(code);
    long(code, 0);
    far(code, OUTPUT);
    far(code, SIZE);
    call(code, module, get, 0);
    compare(code, SIZE, expected.len() as u16);
    compare(code, SIZE + 2, 0);
    for (offset, byte) in expected.iter().copied().chain([0xcc]).enumerate() {
        code.emit(&[0x80, 0x3e]);
        code.word(OUTPUT + offset as u16);
        code.emit(&[byte]);
        code.fail_if(0x85);
    }
    if module == 1 {
        // KERNEL's Win32 thunk distinguishes a zero-capacity buffer from NULL.
        store(code, SIZE, 0);
        store(code, OUTPUT, 0xcccc);
        key(code);
        long(code, 0);
        far(code, OUTPUT);
        far(code, SIZE);
        call(code, module, get, 234);
        compare(code, SIZE, expected.len() as u16);
        compare(code, OUTPUT, 0xcccc);
    }
}

pub fn registry_query_program(path: &str) -> Vec<u8> {
    assert!(path.starts_with("Compat16Test.") && path.is_ascii());
    assert!(!path.contains(['\\', '/', '\0']));
    let mut data = vec![0_u8; 512];
    data[PATH as usize..PATH as usize + path.len()].copy_from_slice(path.as_bytes());
    data[128..136].copy_from_slice(b"missing\0");
    let mut code = Code::default();
    for (module, create, set, get, close, delete) in
        [(2, 2, 5, 6, 3, 4), (1, 218, 221, 224, 220, 219)]
    {
        long(&mut code, 0x8000_0001);
        far(&mut code, PATH);
        far(&mut code, KEY);
        call(&mut code, module, create, 0);
        for text in [b"Test\xd6\xd0\0".as_slice(), b"\0".as_slice()] {
            for (offset, byte) in text.iter().copied().enumerate() {
                code.emit(&[0xc6, 0x06]);
                code.word(TEXT + offset as u16);
                code.emit(&[byte]);
            }
            key(&mut code);
            long(&mut code, 0);
            long(&mut code, 1);
            far(&mut code, TEXT);
            long(&mut code, 0);
            call(&mut code, module, set, 0);
            size_and_read(&mut code, module, get, text);
        }
        // Size-only queries must still expose native key lookup failures.
        store(&mut code, OUTPUT, 0xcccc);
        key(&mut code);
        far(&mut code, 128);
        long(&mut code, 0);
        far(&mut code, SIZE);
        call(&mut code, module, get, 2);
        compare(&mut code, OUTPUT, 0xcccc);
        key(&mut code);
        call(&mut code, module, close, 0);
        key(&mut code);
        long(&mut code, 0);
        long(&mut code, 0);
        far(&mut code, SIZE);
        call(&mut code, module, get, if module == 2 { 8 } else { 6 });
        long(&mut code, 0x8000_0001);
        far(&mut code, PATH);
        call(&mut code, module, delete, 0);
    }
    ne(
        "REGSIZE",
        &code.finish(),
        &data,
        &["KERNEL", "SHELL"],
        false,
    )
}
