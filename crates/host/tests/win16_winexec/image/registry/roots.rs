//! Win3.1's default-root node and Win32 predefined handles stay distinct.
use super::{Code, KEY, OUTPUT, PATH, SIZE, call, compare, far, key, long, ne, store};

fn read(code: &mut Code, module: u16, root: u32, subkey: u16, status: u16) {
    store(code, SIZE, 64);
    store(code, SIZE + 2, 0);
    store(code, OUTPUT, 0xcccc);
    long(code, root);
    far(code, subkey);
    far(code, OUTPUT);
    far(code, SIZE);
    call(code, module, if module == 2 { 6 } else { 224 }, status);
    if status == 0 {
        compare(code, SIZE, 9);
        for (offset, byte) in b"RootText\0".iter().copied().enumerate() {
            code.emit(&[0x80, 0x3e]);
            code.word(OUTPUT + offset as u16);
            code.emit(&[byte]);
            code.fail_if(0x85);
        }
    } else {
        compare(code, SIZE, 64);
        compare(code, OUTPUT, 0xcccc);
    }
}

pub fn registry_roots_program(name: &str) -> Vec<u8> {
    assert!(
        name.starts_with("Compat16Test.") && name.is_ascii() && !name.contains(['\\', '/', '\0'])
    );
    let mut data = vec![0u8; 512];
    data[PATH as usize..PATH as usize + name.len()].copy_from_slice(name.as_bytes());
    data[32..41].copy_from_slice(b".ClAsSeS\0");
    let literal = format!(".classes\\{name}\0");
    data[128..128 + literal.len()].copy_from_slice(literal.as_bytes());
    let mut code = Code::default();
    // This opens a logical root; the fixture performs no registry writes.
    long(&mut code, 0);
    far(&mut code, 32);
    far(&mut code, KEY);
    call(&mut code, 2, 1, 0);
    store(&mut code, SIZE, 64);
    key(&mut code);
    far(&mut code, PATH);
    far(&mut code, OUTPUT);
    far(&mut code, SIZE);
    call(&mut code, 2, 6, 0);
    compare(&mut code, SIZE, 9);
    compare(&mut code, OUTPUT, 0x6f52);
    key(&mut code);
    call(&mut code, 2, 3, 0);
    for root in [0, 1, 0x8000_0000] {
        read(&mut code, 2, root, PATH, 0);
    }
    read(&mut code, 1, 0x8000_0000, PATH, 0);
    for root in [0, 1] {
        read(&mut code, 1, root, PATH, 6);
    }
    // The literal node name remains a normal subkey for other roots/APIs.
    read(&mut code, 2, 1, 128, 2);
    read(&mut code, 1, 0x8000_0000, 128, 2);
    long(&mut code, 0);
    call(&mut code, 2, 3, 8);
    long(&mut code, 0);
    long(&mut code, 0);
    far(&mut code, OUTPUT);
    long(&mut code, 64);
    call(&mut code, 2, 7, 8);
    for root in [0, 1] {
        long(&mut code, root);
        call(&mut code, 1, 220, 6);
    }
    ne(
        "REGROOTS",
        &code.finish(),
        &data,
        &["KERNEL", "SHELL"],
        false,
    )
}
