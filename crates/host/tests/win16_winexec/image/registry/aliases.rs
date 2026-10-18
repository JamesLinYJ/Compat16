//! Actual enumerated names must address the same native key in every API.
use super::{Code, KEY, OUTPUT, SIZE, call, compare, far, key, key_at, long, ne, store};

const PARENT: u16 = 12;
const OTHER: u16 = 16;
const NAME: [u16; 2] = [512, 576];
const NESTED: u16 = 640;
const FULL: u16 = 704;
const DBCS: u16 = 832;
const PATH: u16 = 256;
const CHILD: u16 = 32;
const INVALID: u16 = 176;

fn expect_bytes(code: &mut Code, offset: u16, bytes: &[u8]) {
    for (index, byte) in bytes.iter().copied().enumerate() {
        code.emit(&[0x80, 0x3e]);
        code.word(offset + index as u16);
        code.emit(&[byte]);
        code.fail_if(0x85);
    }
}

fn copy(code: &mut Code, from: u16, to: u16, count: u16) {
    for index in 0..count {
        code.emit(&[0xa0]);
        code.word(from + index);
        code.emit(&[0xa2]);
        code.word(to + index);
    }
}

fn query(code: &mut Code, module: u16, handle: u16, path: u16, value: &[u8], status: u16) {
    store(code, SIZE, 64);
    store(code, SIZE + 2, 0);
    store(code, OUTPUT, 0xcccc);
    key_at(code, handle);
    far(code, path);
    far(code, OUTPUT);
    far(code, SIZE);
    call(code, module, if module == 2 { 6 } else { 224 }, status);
    if status == 0 {
        compare(code, SIZE, value.len() as u16 + 1);
        expect_bytes(code, OUTPUT, value);
        expect_bytes(code, OUTPUT + value.len() as u16, &[0]);
    } else {
        compare(code, SIZE, 64);
        compare(code, OUTPUT, 0xcccc);
    }
}

fn open(code: &mut Code, module: u16, create: bool, path: u16, output: u16, status: u16) {
    key(code);
    far(code, path);
    far(code, output);
    let ordinal = match (module, create) {
        (2, false) => 1,
        (2, true) => 2,
        (_, false) => 217,
        (_, true) => 218,
    };
    call(code, module, ordinal, status);
}

fn close(code: &mut Code, module: u16, handle: u16) {
    key_at(code, handle);
    call(code, module, if module == 2 { 3 } else { 220 }, 0);
}

fn enumerate(
    code: &mut Code,
    module: u16,
    handle: u16,
    index: u32,
    out: u16,
    size: u32,
    status: u16,
) {
    key_at(code, handle);
    long(code, index);
    far(code, out);
    long(code, size);
    call(code, module, if module == 2 { 7 } else { 216 }, status);
}

fn set(code: &mut Code, module: u16, path: u16, value: u16) {
    key(code);
    far(code, path);
    long(code, 1);
    far(code, value);
    long(code, 0);
    call(code, module, if module == 2 { 5 } else { 221 }, 0);
}

pub fn registry_aliases_program(
    name: &str,
    module: u16,
    values: [&[u8]; 2],
    unicode_index: usize,
) -> Vec<u8> {
    let mut data = vec![0_u8; 1024];
    data[PATH as usize..PATH as usize + name.len()].copy_from_slice(name.as_bytes());
    for (offset, bytes) in [
        (80, b"Updated0\0".as_slice()),
        (96, b"Updated1\0".as_slice()),
        (112, b"NestedUpdated\0".as_slice()),
        (160, b"Other\0".as_slice()),
    ] {
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    data[INVALID as usize..INVALID as usize + 37]
        .copy_from_slice(b"~C16~00000000000000000000000000000000");
    let mut code = Code::default();
    let root = if module == 2 { 1 } else { 0x8000_0000 };
    long(&mut code, root);
    far(&mut code, PATH);
    far(&mut code, KEY);
    call(&mut code, module, if module == 2 { 1 } else { 217 }, 0);
    for index in 0..2 {
        let out = NAME[index];
        store(&mut code, out, 0xcccc);
        enumerate(
            &mut code,
            module,
            KEY,
            index as u32,
            out,
            37,
            if module == 2 { 7 } else { 234 },
        );
        compare(&mut code, out, 0xcccc);
        store(&mut code, out + 38, 0xa5a5);
        enumerate(&mut code, module, KEY, index as u32, out, 38, 0);
        expect_bytes(&mut code, out, b"~C16~");
        compare(&mut code, out + 37, 0xa500);
        expect_bytes(&mut code, out + 39, &[0xa5]);
        query(&mut code, module, KEY, out, values[index], 0);
        // Closing and reopening the fixture must not invalidate saved names.
        close(&mut code, module, KEY);
        long(&mut code, root);
        far(&mut code, PATH);
        far(&mut code, KEY);
        call(&mut code, module, if module == 2 { 1 } else { 217 }, 0);
        // Alias tokens are case insensitive, just like native key names.
        code.emit(&[0xc6, 0x06]);
        code.word(out + 1);
        code.emit(b"c");
        open(&mut code, module, false, out, CHILD, 0);
        query(&mut code, module, CHILD, 240, values[index], 0);
        close(&mut code, module, CHILD);
        set(&mut code, module, out, 80 + index as u16 * 16);
        open(&mut code, module, true, out, CHILD, 0);
        query(
            &mut code,
            module,
            CHILD,
            240,
            if index == 0 { b"Updated0" } else { b"Updated1" },
            0,
        );
        close(&mut code, module, CHILD);
    }
    // Unknown aliases are identities, never literal names to create.
    for create in [false, true] {
        open(&mut code, module, create, INVALID, CHILD, 2);
    }
    query(&mut code, module, KEY, INVALID, &[], 2);
    key(&mut code);
    far(&mut code, INVALID);
    long(&mut code, 1);
    far(&mut code, 80);
    long(&mut code, 0);
    call(&mut code, module, if module == 2 { 5 } else { 221 }, 2);
    key(&mut code);
    far(&mut code, INVALID);
    call(&mut code, module, if module == 2 { 4 } else { 219 }, 2);
    // A name from another parent cannot resolve through a global alias table.
    open(&mut code, module, false, NAME[1 - unicode_index], PARENT, 0);
    key_at(&mut code, PARENT);
    far(&mut code, 160);
    far(&mut code, OTHER);
    call(&mut code, module, if module == 2 { 1 } else { 217 }, 0);
    close(&mut code, module, PARENT);
    query(&mut code, module, OTHER, NAME[unicode_index], &[], 2);
    enumerate(
        &mut code,
        module,
        OTHER,
        0,
        NESTED,
        64,
        if module == 2 { 2 } else { 259 },
    );
    close(&mut code, module, OTHER);
    // Resolve two alias components in the same path, then mutate/delete only
    // the native nested key. The intermediate temporary native key is owned.
    open(&mut code, module, false, NAME[unicode_index], PARENT, 0);
    enumerate(&mut code, module, PARENT, 0, DBCS, 64, 0);
    expect_bytes(&mut code, DBCS, b"\x81\x5c\0");
    query(&mut code, module, PARENT, DBCS, b"Dbcs", 0);
    key_at(&mut code, PARENT);
    far(&mut code, DBCS);
    far(&mut code, OTHER);
    call(&mut code, module, if module == 2 { 1 } else { 217 }, 0);
    enumerate(&mut code, module, OTHER, 0, NESTED, 64, 0);
    query(&mut code, module, OTHER, NESTED, b"Nested", 0);
    copy(&mut code, NAME[unicode_index], FULL, 37);
    code.emit(&[0xc6, 0x06]);
    code.word(FULL + 37);
    code.emit(b"\\");
    copy(&mut code, DBCS, FULL + 38, 2);
    code.emit(&[0xc6, 0x06]);
    code.word(FULL + 40);
    code.emit(b"\\");
    copy(&mut code, NESTED, FULL + 41, 38);
    query(&mut code, module, KEY, FULL, b"Nested", 0);
    set(&mut code, module, FULL, 112);
    open(&mut code, module, false, FULL, CHILD, 0);
    query(&mut code, module, CHILD, 240, b"NestedUpdated", 0);
    close(&mut code, module, CHILD);
    key(&mut code);
    far(&mut code, FULL);
    call(&mut code, module, if module == 2 { 4 } else { 219 }, 0);
    enumerate(
        &mut code,
        module,
        OTHER,
        0,
        NESTED,
        64,
        if module == 2 { 2 } else { 259 },
    );
    close(&mut code, module, OTHER);
    close(&mut code, module, PARENT);
    close(&mut code, module, KEY);
    ne(
        "REGALIAS",
        &code.finish(),
        &data,
        &["KERNEL", "SHELL"],
        false,
    )
}
