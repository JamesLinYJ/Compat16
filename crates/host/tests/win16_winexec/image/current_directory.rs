//! Check the DOS return used for bounded ASCIIZ scanning on both guest routes.

use super::{Code, ne};

fn query(code: &mut Code, dos3call: bool, drive: u8) {
    code.immediate(0xbe, 0x100); // SI points to a 64-byte owned destination.
    code.emit(&[0x1e, 0x07, 0x89, 0xf7]); // ES=DS; DI=SI.
    code.immediate(0xb9, 64);
    code.immediate(0xb8, 0x00a5);
    code.emit(&[0xfc, 0xf3, 0xaa]); // Clear old terminators before each route.
    code.immediate(0xba, u16::from(drive));
    code.immediate(0xb8, 0x4743); // Deliberately leave a nonzero input AL.
    if dos3call {
        code.call(102); // KERNEL.DOS3Call.
    } else {
        code.emit(&[0xcd, 0x21]);
    }
    code.fail_if(0x82); // JC.
    code.immediate(0x3d, 0x0100); // The complete DOS success value.
    code.fail_if(0x85);
    code.immediate(0xb9, 64);
    let scan = code.bytes.len();
    code.emit(&[0x3a, 0x04]); // CMP AL,[SI], as used by legacy pathname code.
    code.emit(&[0x74, 0x04, 0x46, 0xe2]); // JE done; INC SI; LOOP scan.
    code.bytes
        .push(i8::try_from(scan as isize - (code.bytes.len() + 1) as isize).unwrap() as u8);
    code.emit(&[0xf9]); // STC when no terminator was found within 64 bytes.
    code.fail_if(0x82);
}

pub fn current_directory_program() -> Vec<u8> {
    let mut code = Code::default();
    query(&mut code, false, 0);
    query(&mut code, true, 0);
    ne("CURDIR", &code.finish(), &[0xa5; 512], &["KERNEL"], false)
}

pub fn current_directory_com() -> Vec<u8> {
    let mut code = Code::default();
    // A COM image has DS=CS; use a trailing buffer instead of its own code.
    query(&mut code, false, 0);
    let mut code = code.finish();
    let buffer = 0x100 + code.bytes.len();
    code.bytes[1..3].copy_from_slice(&u16::try_from(buffer).unwrap().to_le_bytes());
    code.bytes.extend([0xa5; 64]);
    code.bytes
}
