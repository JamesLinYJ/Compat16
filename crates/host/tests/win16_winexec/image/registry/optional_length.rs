//! Optional length pointers have different SHELL and KERNEL contracts.
use super::{Code, KEY, OUTPUT, PATH, TEXT, call, compare, far, key, long, ne, store};

pub fn registry_optional_length_program(path: &str) -> Vec<u8> {
    assert!(
        path.starts_with("Compat16Test.") && path.is_ascii() && !path.contains(['\\', '/', '\0'])
    );
    let mut data = vec![0_u8; 512];
    data[PATH as usize..PATH as usize + path.len()].copy_from_slice(path.as_bytes());
    data[TEXT as usize..TEXT as usize + 7].copy_from_slice(b"Test\xd6\xd0\0");
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
        for missing in [false, true] {
            for output in [0, u32::from(OUTPUT), 0xffff_0001] {
                store(&mut code, OUTPUT, 0xcccc);
                key(&mut code);
                if missing {
                    far(&mut code, 128);
                } else {
                    long(&mut code, 0);
                }
                if output == u32::from(OUTPUT) {
                    far(&mut code, OUTPUT);
                } else {
                    long(&mut code, output);
                }
                long(&mut code, 0);
                let status = if module == 2 {
                    7
                } else if missing {
                    2
                } else if output == 0 {
                    0
                } else {
                    87
                };
                call(&mut code, module, get, status);
                compare(&mut code, OUTPUT, 0xcccc);
            }
        }
        if module == 2 {
            // SHELL rejects NULL lpcbData before touching the other pointers.
            key(&mut code);
            long(&mut code, 0xffff_0001);
            long(&mut code, 0xffff_0001);
            long(&mut code, 0);
            call(&mut code, module, get, 7);
        }
        key(&mut code);
        call(&mut code, module, close, 0);
        key(&mut code);
        long(&mut code, 0);
        long(&mut code, 0);
        long(&mut code, 0);
        call(&mut code, module, get, if module == 2 { 7 } else { 6 });
        long(&mut code, 0x8000_0001);
        far(&mut code, PATH);
        call(&mut code, module, delete, 0);
    }
    ne(
        "REGOPTION",
        &code.finish(),
        &data,
        &["KERNEL", "SHELL"],
        false,
    )
}
