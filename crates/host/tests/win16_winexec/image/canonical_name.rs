//! AH=60h strings, overlap, error preservation and opening the aliased result.
use super::{Code, ne};

fn compare(code: &mut Code, register: u8, value: u16) {
    code.emit(&[0x81, 0xf8 + register]);
    code.word(value);
    code.fail_if(0x85);
}
fn invoke(code: &mut Code, source: u16, output: u16, thunk: bool, error: Option<u16>) {
    code.immediate(0xbe, source);
    code.immediate(0xbf, output);
    code.immediate(0xbb, 0x2345);
    code.immediate(0xb9, 0x3456);
    code.immediate(0xba, 0x4567);
    code.immediate(0xb8, 0x6000);
    code.emit(&[0xf9]);
    if thunk {
        code.call(102);
    } else {
        code.emit(&[0xcd, 0x21]);
    }
    code.fail_if(if error.is_some() { 0x83 } else { 0x82 });
    if let Some(error) = error {
        compare(code, 0, error);
    } else {
        code.emit(&[0x80, 0xfc, 0]);
        code.fail_if(0x85);
    }
    compare(code, 3, 0x2345);
    compare(code, 1, 0x3456);
    compare(code, 2, 0x4567);
    compare(code, 6, source);
    compare(code, 7, output);
}
fn equal(code: &mut Code, left: u16, right: u16, length: u16) {
    code.immediate(0xbe, left);
    code.immediate(0xbf, right);
    code.immediate(0xb9, length);
    code.emit(&[0xfc, 0xf3, 0xa6]);
    code.fail_if(0x85);
}

pub fn canonical_name_program(protected: bool, prc: bool) -> Vec<u8> {
    let base = if protected { 0 } else { 0x3000 };
    let mut data = vec![0xa5; 0x1000];
    let mut code = Code::default();
    code.emit(&[0x1e, 0x07]);
    // Rooted input gives a deterministic expected path on the current drive.
    let rooted = b"/absent/../missing/file*.toolong\0";
    data[0x100..0x100 + rooted.len()].copy_from_slice(rooted);
    let expected = b"C:\\MISSING\\FILE????.TOO\0";
    data[0x200..0x200 + expected.len()].copy_from_slice(expected);
    code.interrupt(0x1900);
    code.emit(&[0x04, b'A', 0xa2]);
    code.word(base + 0x200);
    let long = b".\\Long file name.txt\0";
    data[0x300..0x300 + long.len()].copy_from_slice(long);
    let directory = b"Long directory name\0";
    data[0xe00..0xe00 + directory.len()].copy_from_slice(directory);
    data[0xf00..0xf03].copy_from_slice(b"..\0");
    let oem = if prc {
        b".\\\x81\\a.txt\0".as_slice()
    } else {
        b".\\\x81a.txt\0"
    };
    data[0x400..0x400 + oem.len()].copy_from_slice(oem);
    let bad = b"\\..\\bad.txt\0";
    data[0x500..0x500 + bad.len()].copy_from_slice(bad);
    for thunk in [false, true]
        .into_iter()
        .take(if protected { 2 } else { 1 })
    {
        // Lexical path is independent of nonexistent entries.
        invoke(&mut code, base + 0x100, base + 0x600, thunk, None);
        equal(&mut code, base + 0x600, base + 0x200, expected.len() as u16);
        equal(&mut code, base + 0x680, base + 0x700, 4);
        // Failed translation does not touch any of the 128 destination bytes.
        invoke(&mut code, base + 0x500, base + 0x800, thunk, Some(3));
        equal(&mut code, base + 0x800, base + 0x900, 132);
        for source in [base + 0x300, base + 0x400] {
            // DOS directory changes are owner-retained in Win16. AH=60h
            // must activate that task context before consulting the host cwd.
            code.immediate(
                0xba,
                if source == base + 0x300 {
                    base + 0xe00
                } else {
                    base + 0xf00
                },
            );
            code.interrupt(0x3b00);
            code.fail_if(0x82);
            invoke(&mut code, source, base + 0xa00, thunk, None);
            equal(&mut code, base + 0xa80, base + 0x700, 4);
            code.immediate(0xba, base + 0xa00);
            code.interrupt(0x3d00);
            code.fail_if(0x82);
            code.emit(&[0x89, 0xc3]);
            code.immediate(0xb9, 3);
            code.immediate(0xba, base + 0xb00);
            code.interrupt(0x3f00);
            code.fail_if(0x82);
            compare(&mut code, 0, 3);
            code.interrupt(0x3e00);
            code.fail_if(0x82);
            data[0xc00..0xc03].copy_from_slice(b"one");
            equal(&mut code, base + 0xb00, base + 0xc00, 3);
        }
        // The same 128-byte range may be input and output.
        code.immediate(0xbe, base + 0x100);
        code.immediate(0xbf, base + 0xd00);
        code.immediate(0xb9, rooted.len() as u16);
        code.emit(&[0xfc, 0xf3, 0xa4]);
        invoke(&mut code, base + 0xd00, base + 0xd00, thunk, None);
        equal(&mut code, base + 0xd00, base + 0x200, expected.len() as u16);
    }
    let code = code.finish();
    if protected {
        ne("CANON", &code, &data, &["KERNEL"], false)
    } else {
        let mut bytes = code.bytes;
        assert!(bytes.len() <= usize::from(base - 0x100));
        bytes.resize(usize::from(base - 0x100), 0);
        bytes.extend_from_slice(&data);
        bytes
    }
}
