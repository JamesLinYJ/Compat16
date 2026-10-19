//! Win3.1 string projection is separate from the native KERNEL query contract.
use super::{Code, KEY, OUTPUT, PATH, SIZE, call, compare, far, key, long, ne, store};

const CHILD: u16 = 512;

fn expect(code: &mut Code, offset: u16, bytes: &[u8]) {
    for (index, byte) in bytes.iter().copied().enumerate() {
        code.emit(&[0x80, 0x3e]);
        code.word(offset + index as u16);
        code.emit(&[byte]);
        code.fail_if(0x85);
    }
}

fn query(
    code: &mut Code,
    module: u16,
    child: u16,
    capacity: u16,
    size_only: bool,
    expected: &[u8],
    error: u16,
) {
    store(code, SIZE, capacity);
    store(code, SIZE + 2, 0);
    for offset in (0..66).step_by(2) {
        store(code, OUTPUT + offset, 0xcccc);
    }
    key(code);
    far(code, child);
    if size_only {
        long(code, 0);
    } else {
        far(code, OUTPUT);
    }
    far(code, SIZE);
    call(code, module, if module == 2 { 6 } else { 224 }, error);
    if error != 0 {
        compare(code, SIZE, capacity);
        compare(code, OUTPUT, 0xcccc);
    } else {
        let returned = if size_only {
            expected.len()
        } else {
            expected.len().min(capacity as usize)
        };
        compare(code, SIZE, returned as u16);
        compare(code, SIZE + 2, 0);
        if size_only {
            compare(code, OUTPUT, 0xcccc);
        } else {
            expect(code, OUTPUT, &expected[..returned]);
            expect(code, OUTPUT + returned as u16, &[0xcc]);
        }
    }
}

pub fn registry_expand_program(path: &str, module: u16) -> Vec<u8> {
    assert!(
        path.starts_with("Compat16Test.") && path.is_ascii() && !path.contains(['\\', '/', '\0'])
    );
    assert!(matches!(module, 1 | 2));
    let mut data = vec![0; 1024];
    data[PATH as usize..PATH as usize + path.len()].copy_from_slice(path.as_bytes());
    let mut code = Code::default();
    long(&mut code, 0x8000_0001);
    far(&mut code, PATH);
    far(&mut code, KEY);
    call(&mut code, module, if module == 2 { 1 } else { 217 }, 0);
    let raw = b"\xc7\xb0%SystemRoot%\\\xce\xb2%Compat16MissingVariable%\0";
    for (index, (name, value, expand)) in [
        ("Expand", raw.as_slice(), true),
        ("Empty", b"\0".as_slice(), true),
        ("NoExplicitNul", b"\xc7\xb0\0".as_slice(), true),
        ("Plain", b"Keep\0".as_slice(), false),
        ("Absent", b"\0".as_slice(), false),
    ]
    .into_iter()
    .enumerate()
    {
        let child = CHILD + index as u16 * 32;
        data[child as usize..child as usize + name.len()].copy_from_slice(name.as_bytes());
        let error = if module == 1 && expand { 13 } else { 0 };
        query(&mut code, module, child, 64, true, value, error);
        query(&mut code, module, child, 64, false, value, error);
        if module == 2 && expand {
            // Win3.1 returns exactly the low-capacity bytes, even a DBCS lead
            // without its trail. No invented terminator is copied on truncation.
            query(&mut code, module, child, 1, false, value, 0);
            query(&mut code, module, child, 0, false, value, 0);
        }
    }
    for (index, name, error) in [
        (5, "Binary", if module == 2 { 8 } else { 13 }),
        (6, "Missing", 2),
    ] {
        let child = CHILD + index * 32;
        data[child as usize..child as usize + name.len()].copy_from_slice(name.as_bytes());
        query(&mut code, module, child, 64, false, b"", error);
    }
    key(&mut code);
    call(&mut code, module, if module == 2 { 3 } else { 220 }, 0);
    ne(
        "REGEXPAND",
        &code.finish(),
        &data,
        &["KERNEL", "SHELL"],
        false,
    )
}
