//! Guest-observed AH=29h fields and SI through both protected DOS entries.
use super::{Code, ne};

const INITIAL: [u8; 16] = *b"\x02OLDNAME XYZ\xa1\xa2\xa3\xa4";

fn fcb(drive: u8, name: &[u8; 11]) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[0] = drive;
    bytes[1..12].copy_from_slice(name);
    bytes
}

fn compare(code: &mut Code, mod_rm: u8, expected: u16) {
    code.emit(&[0x81, mod_rm]);
    code.word(expected);
    code.fail_if(0x85);
}

pub fn fcb_parse_program(protected: bool, dbcs: bool) -> Vec<u8> {
    let mut cases: Vec<(&[u8], u8, u8, u16, [u8; 16])> = vec![
        (b"c:readme.txt rest\0", 0, 0, 12, fcb(3, b"README  TXT")),
        (b" \t,foo?.* tail\0", 1, 1, 9, fcb(0, b"FOO?    ???")),
        (b"\r", 14, 0, 0, fcb(2, b"OLDNAME XYZ")),
        (b".\0", 14, 0, 1, fcb(2, b"OLDNAME    ")),
        (b"abcdefghijkl.abcd\0", 0, 0, 17, fcb(0, b"ABCDEFGHABC")),
        (b"1:foo.bin\0", 0, 0xff, 9, fcb(0xf1, b"FOO     BIN")),
        (
            b"\x81a.txt\0",
            0,
            0,
            6,
            fcb(
                0,
                if dbcs {
                    b"\x81a      TXT"
                } else {
                    b"\x9aA      TXT"
                },
            ),
        ),
    ];
    if dbcs {
        cases.push((
            b"\xa1\xa1a\x81\\b.t\x81?\0",
            0,
            0,
            10,
            fcb(0, b"A\x81\\B    T\x81?"),
        ));
    } else {
        cases.push((b"?fname.???\0", 0, 1, 10, fcb(0, b"?FNAME  ???")));
    }
    let mut data = vec![0xa5; 0x2000];
    let data_base = if protected { 0 } else { 0x3000_u16 };
    let mut code = Code::default();
    code.emit(&[0x1e, 0x07]); // ES=DS; selectors remain selectors in NE mode.
    for thunk in [false, true]
        .into_iter()
        .take(if protected { 2 } else { 1 })
    {
        for (index, (input, flags, status, consumed, expected)) in cases.iter().enumerate() {
            let output = 0x100 + index * 32;
            let reference = 0x800 + index * 32;
            let source = 0x1000 + index * 64;
            data[output..output + 16].copy_from_slice(&INITIAL);
            data[reference..reference + 16].copy_from_slice(expected);
            data[source..source + input.len()].copy_from_slice(input);
            code.immediate(0xb8, 0x2900 | u16::from(*flags));
            code.immediate(0xbb, 0x2345);
            code.immediate(0xb9, 0x3456);
            code.immediate(0xba, 0x4567);
            code.immediate(0xbe, data_base + source as u16);
            code.immediate(0xbf, data_base + output as u16);
            if thunk {
                code.call(102);
            } else {
                code.emit(&[0xcd, 0x21]);
            }
            code.emit(&[0x3c, *status]);
            code.fail_if(0x85);
            compare(&mut code, 0xfe, data_base + source as u16 + consumed);
            compare(&mut code, 0xff, data_base + output as u16);
            compare(&mut code, 0xfb, 0x2345);
            compare(&mut code, 0xf9, 0x3456);
            compare(&mut code, 0xfa, 0x4567);
            code.immediate(0xbe, data_base + reference as u16);
            code.immediate(0xbf, data_base + output as u16);
            code.immediate(0xb9, 32);
            code.emit(&[0xfc, 0xf3, 0xa6]); // Compare result and untouched guard.
            code.fail_if(0x85);
        }
    }
    let code = code.finish();
    if protected {
        ne("FCBPARSE", &code, &data, &["KERNEL"], false)
    } else {
        let mut bytes = code.bytes;
        assert!(bytes.len() <= usize::from(data_base - 0x100));
        bytes.resize(usize::from(data_base - 0x100), 0);
        bytes.extend_from_slice(&data);
        bytes
    }
}
