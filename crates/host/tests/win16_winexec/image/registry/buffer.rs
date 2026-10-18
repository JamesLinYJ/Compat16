//! Real SHELL truncation and bounded Win32 queries over the same registry value.
use super::{Code, KEY, OUTPUT, PATH, SIZE, TEXT, call, compare, far, key, long, ne, store};

const VALUE: &[u8] = b"Test\xd6\xd0\0";

fn check(code: &mut Code, module: u16, get: u16, capacity: u32) {
    store(code, SIZE, capacity as u16);
    store(code, SIZE + 2, (capacity >> 16) as u16);
    for offset in (0..16).step_by(2) {
        store(code, OUTPUT + offset, 0xcccc);
    }
    key(code);
    long(code, 0);
    far(code, OUTPUT);
    far(code, SIZE);
    let short = capacity < VALUE.len() as u32;
    call(
        code,
        module,
        get,
        if module == 1 && short { 234 } else { 0 },
    );
    let copied = if short && module == 1 {
        0
    } else {
        VALUE.len().min(capacity as usize)
    };
    let reported = if module == 2 {
        VALUE.len().min(capacity as usize)
    } else {
        VALUE.len()
    };
    compare(code, SIZE, reported as u16);
    compare(code, SIZE + 2, 0);
    for (offset, byte) in VALUE[..copied].iter().copied().chain([0xcc]).enumerate() {
        code.emit(&[0x80, 0x3e]);
        code.word(OUTPUT + offset as u16);
        code.emit(&[byte]);
        code.fail_if(0x85);
    }
}

pub fn registry_buffer_program(path: &str) -> Vec<u8> {
    assert!(
        path.starts_with("Compat16Test.") && path.is_ascii() && !path.contains(['\\', '/', '\0'])
    );
    let mut data = vec![0_u8; 512];
    data[PATH as usize..PATH as usize + path.len()].copy_from_slice(path.as_bytes());
    data[TEXT as usize..TEXT as usize + VALUE.len()].copy_from_slice(VALUE);
    data[128..136].copy_from_slice(b"missing\0");
    let mut code = Code::default();
    for (module, create, set, get, close, delete) in
        [(2, 2, 5, 6, 3, 4), (1, 218, 221, 224, 220, 219)]
    {
        long(&mut code, 0x8000_0001);
        far(&mut code, PATH);
        far(&mut code, KEY);
        call(&mut code, module, create, 0);
        key(&mut code);
        long(&mut code, 0);
        long(&mut code, 1);
        far(&mut code, TEXT);
        long(&mut code, 0);
        call(&mut code, module, set, 0);
        for capacity in [0, 1, 5, 6, 7, 8, 0x1_0000, 0x8000_0000, u32::MAX] {
            check(&mut code, module, get, capacity);
        }
        // Neither missing keys nor invalid handles may clobber a length output.
        store(&mut code, SIZE, 0x5678);
        store(&mut code, SIZE + 2, 0x1234);
        store(&mut code, OUTPUT, 0xcccc);
        key(&mut code);
        far(&mut code, 128);
        far(&mut code, OUTPUT);
        far(&mut code, SIZE);
        call(&mut code, module, get, 2);
        compare(&mut code, SIZE, 0x5678);
        compare(&mut code, SIZE + 2, 0x1234);
        compare(&mut code, OUTPUT, 0xcccc);
        key(&mut code);
        call(&mut code, module, close, 0);
        key(&mut code);
        long(&mut code, 0);
        far(&mut code, OUTPUT);
        far(&mut code, SIZE);
        call(&mut code, module, get, if module == 2 { 8 } else { 6 });
        compare(&mut code, SIZE, 0x5678);
        compare(&mut code, SIZE + 2, 0x1234);
        long(&mut code, 0x8000_0001);
        far(&mut code, PATH);
        call(&mut code, module, delete, 0);
    }
    ne(
        "REGBUFFER",
        &code.finish(),
        &data,
        &["KERNEL", "SHELL"],
        false,
    )
}
