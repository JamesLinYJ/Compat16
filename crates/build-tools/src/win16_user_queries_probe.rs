//! Read-only USER queries executed by a repository-authored 16-bit NE guest.
use crate::probe::{CodeBuilder, ProbeBuildError};
use crate::win16_dialog_probe::{build_image_with_import, imported_call};

// ASCII is stable across native ANSI code pages. Deliberately dirty the high
// byte of each WORD slot: the APIs classify only its low byte.
const CLASSIFICATIONS: [(u16, [u16; 4]); 4] = [
    (433, [1, 1, 0, 0]),
    (434, [1, 1, 1, 0]),
    (435, [1, 0, 0, 0]),
    (436, [0, 1, 0, 0]),
];
const INPUTS: [u16; 4] = [0xff41, 0xff61, 0xff30, 0xff21];

/// No windows, resources, input writes, or cursor ownership changes. Dynamic
/// query results are not fixed: AnyPopup may be either BOOL, GetCursor may be
/// NULL, and native GetClipCursor failure may retain all eight output bytes.
pub fn win16_user_queries_probe_bytes() -> Result<Vec<u8>, ProbeBuildError> {
    let (code, fixups) = guest_code()?;
    build_image_with_import(&code, &fixups, 24, b"USER", false)
}

fn require(code: &mut CodeBuilder, success: u8, status: u8) {
    code.emit(&[success, 5, 0xb8, status, 0x4c, 0xcd, 0x21]);
}

fn immediate32(code: &mut CodeBuilder, opcode: &[u8], value: u32) {
    code.emit(opcode);
    code.emit(&value.to_le_bytes());
}

fn prepare(code: &mut CodeBuilder) {
    // Operand-size overrides in a 16-bit code segment expose accidental upper
    // register writes. The call itself and Pascal argument slots remain 16-bit.
    for (opcode, value) in [
        (0xb8, 0x1234_a55a), (0xba, 0x5678_5aa5), (0xbb, 0x9abc_1357),
        (0xb9, 0xabcd_2468), (0xbe, 0xbcde_369c), (0xbf, 0xcdef_48ad),
        (0xbd, 0xdef0_5abe),
    ] {
        immediate32(code, &[0x66, opcode], value);
    }
    code.emit(&[0x1e, 0x07, 0x89, 0x26, 0, 0]); // ES=DS; save SP
    code.emit(&[0x8c, 0x1e, 2, 0]); // save DS independently of API return values
}

fn preserved(code: &mut CodeBuilder) {
    // Check EAX separately according to WORD/VOID return kind, before this
    // helper uses AX for the segment checks. These are runtime ABI regressions.
    for (modrm, value, status) in [
        (0xfa, 0x5678_5aa5, 60), (0xfb, 0x9abc_1357, 61),
        (0xf9, 0xabcd_2468, 62), (0xfe, 0xbcde_369c, 63),
        (0xff, 0xcdef_48ad, 64), (0xfd, 0xdef0_5abe, 65),
    ] {
        immediate32(code, &[0x66, 0x81, modrm], value);
        require(code, 0x74, status);
    }
    // SS is DGROUP. Override DS so a clobbered DS cannot redirect the checks.
    code.emit(&[0x36, 0x3b, 0x26, 0, 0]);
    require(code, 0x74, 66);
    code.emit(&[0x8c, 0xd8, 0x36, 0x3b, 0x06, 2, 0]);
    require(code, 0x74, 67);
    code.emit(&[0x8c, 0xc0, 0x36, 0x3b, 0x06, 2, 0]);
    require(code, 0x74, 68);
}

fn guest_code() -> Result<(Vec<u8>, Vec<[u8; 8]>), ProbeBuildError> {
    let mut code = CodeBuilder::default();
    let mut fixups = Vec::new();
    for (ordinal, expected) in CLASSIFICATIONS {
        for (index, input) in INPUTS.into_iter().enumerate() {
            prepare(&mut code);
            code.emit(&[0x68]);
            code.emit(&input.to_le_bytes()); // exactly one WORD Pascal slot
            imported_call(&mut code, &mut fixups, ordinal);
            immediate32(&mut code, &[0x66, 0x3d], 0x1234_0000 | u32::from(expected[index]));
            require(&mut code, 0x74, 10 + (ordinal - 433) as u8 * 4 + index as u8);
            preserved(&mut code);
        }
    }
    prepare(&mut code);
    imported_call(&mut code, &mut fixups, 52); // AnyPopup, no arguments
    immediate32(&mut code, &[0x66, 0x3d], 0x1234_0000);
    require(&mut code, 0x73, 30); // unsigned >= preserves upper EAX, AX is 0 or 1
    immediate32(&mut code, &[0x66, 0x3d], 0x1234_0001);
    require(&mut code, 0x76, 31);
    code.emit(&[0xa3, 4, 0]); // capture observed BOOL, without assuming desktop state
    preserved(&mut code);

    prepare(&mut code);
    imported_call(&mut code, &mut fixups, 247); // GetCursor, borrowed or NULL
    code.emit(&[0xa3, 6, 0]);
    immediate32(&mut code, &[0x66, 0x25], 0xffff_0000);
    immediate32(&mut code, &[0x66, 0x3d], 0x1234_0000);
    require(&mut code, 0x74, 32);
    preserved(&mut code);

    // DGROUP: SP0, DS2, popup4, cursor6, canary8, RECT10..17, canary18.
    for (offset, value) in [(8u8, 0x1357u16), (10, 0xa55a), (12, 0x5aa5),
        (14, 0x369c), (16, 0x48ad), (18, 0x2468)] {
        code.emit(&[0xc7, 0x06, offset, 0]);
        code.emit(&value.to_le_bytes());
    }
    prepare(&mut code);
    code.emit(&[0x1e, 0x6a, 10]); // RECT FAR*: selector then offset, four Pascal bytes
    imported_call(&mut code, &mut fixups, 309);
    immediate32(&mut code, &[0x66, 0x3d], 0x1234_a55a); // VOID preserves all of EAX
    require(&mut code, 0x74, 33);
    preserved(&mut code); // includes all of EDX and caller SP
    for (offset, value, status) in [(8u8, 0x1357u16, 34), (18, 0x2468, 35)] {
        code.emit(&[0x81, 0x3e, offset, 0]);
        code.emit(&value.to_le_bytes());
        require(&mut code, 0x74, status);
    }
    // Report allowed dynamic outcomes after every ABI assertion has passed.
    // P0/P1: AnyPopup; C0/C1: NULL/non-NULL cursor; R0/R1: unchanged/changed
    // RECT. R0 is not a claim of native success or failure, only observed bytes.
    for (offset, tag, label) in [(4u8, b'P', "popup_output"), (6, b'C', "cursor_output")] {
        code.emit(&[0xc6, 0x06, 21, 0, b'0', 0x83, 0x3e, offset, 0, 0]);
        code.branch(0x74, label);
        code.emit(&[0xc6, 0x06, 21, 0, b'1']);
        code.mark(label);
        output(&mut code, tag);
    }
    code.emit(&[0xc6, 0x06, 21, 0, b'1']);
    for (offset, value) in [(10u8, 0xa55au16), (12, 0x5aa5), (14, 0x369c), (16, 0x48ad)] {
        code.emit(&[0x81, 0x3e, offset, 0]);
        code.emit(&value.to_le_bytes());
        code.branch(0x75, "rect_output");
    }
    code.emit(&[0xc6, 0x06, 21, 0, b'0']);
    code.mark("rect_output");
    output(&mut code, b'R');
    // No invented screen dimensions or nonempty rectangle requirement: native
    // failure is permitted to leave the entire sentinel RECT unchanged.
    code.emit(&[0xb8, 0, 0x4c, 0xcd, 0x21]);
    Ok((code.finish(0)?, fixups))
}

fn output(code: &mut CodeBuilder, tag: u8) {
    code.emit(&[0xc6, 0x06, 20, 0, tag, 0xc6, 0x06, 22, 0, 10]);
    code.emit(&[0xb4, 0x40, 0xbb, 1, 0, 0xb9, 3, 0, 0xba, 20, 0, 0xcd, 0x21]);
    require(code, 0x73, 36); // DOS write must succeed
    code.emit(&[0x3d, 3, 0]);
    require(code, 0x74, 37);
}

#[cfg(test)]
mod tests;
