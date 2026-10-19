//! Alias verification must not rewind the caller's native root enumeration.
use super::{Code, call, compare, far, long, ne, store};

const NAME: u16 = 256;
const OUTPUT: u16 = 128;
const SIZE: u16 = 0;

fn bytes(code: &mut Code, offset: u16, expected: &[u8]) {
    for (index, byte) in expected.iter().copied().enumerate() {
        code.emit(&[0x80, 0x3e]);
        code.word(offset + index as u16);
        code.emit(&[byte]);
        code.fail_if(0x85);
    }
}

pub fn registry_cursor_program(module: u16, index: u32, token: &str) -> Vec<u8> {
    assert!(matches!(module, 1 | 2));
    assert!(token.starts_with("~C16~") && token.len() == 37 && token.is_ascii());
    let root = if module == 2 { 1 } else { 0x8000_0000 };
    let mut code = Code::default();
    for _ in 0..2 {
        store(&mut code, NAME + 38, 0xcccc);
        long(&mut code, root);
        long(&mut code, index);
        far(&mut code, NAME);
        long(&mut code, 64);
        call(&mut code, module, if module == 2 { 7 } else { 216 }, 0);
        bytes(&mut code, NAME, token.as_bytes());
        bytes(&mut code, NAME + 37, &[0, 0xcc]);

        // Resolve the token back to the same live key and read its real value.
        store(&mut code, SIZE, 64);
        store(&mut code, SIZE + 2, 0);
        store(&mut code, OUTPUT + 7, 0xcccc);
        long(&mut code, root);
        far(&mut code, NAME);
        far(&mut code, OUTPUT);
        far(&mut code, SIZE);
        call(&mut code, module, if module == 2 { 6 } else { 224 }, 0);
        compare(&mut code, SIZE, 7);
        bytes(&mut code, OUTPUT, b"Cursor\0\xcc");

        // An out-of-range DWORD index still returns the proper API's status
        // without modifying the last successful output. It also exercises the
        // caller's enumeration after the independent scan has completed.
        long(&mut code, root);
        long(&mut code, u32::MAX);
        far(&mut code, NAME);
        long(&mut code, 64);
        call(
            &mut code,
            module,
            if module == 2 { 7 } else { 216 },
            if module == 2 { 2 } else { 259 },
        );
        bytes(&mut code, NAME, token.as_bytes());
        bytes(&mut code, NAME + 37, &[0]);
    }
    ne(
        "REGCURSOR",
        &code.finish(),
        &[0; 512],
        &["KERNEL", "SHELL"],
        false,
    )
}
