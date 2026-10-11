//! Execute outline metrics through the real Win16 import and guest CPU boundary.
use crate::probe::{CodeBuilder, ProbeBuildError};
use crate::win16_dialog_probe::{build_image_with_import, imported_call};

// DGROUP: DC0, font2, failure4, oldfont6, found8, query10, SP12, DS14,
// LOGFONT16 at 32 (50 bytes), partial canaries126/241, full canary254,
// full buffer256..2303 and canary2304. Stack starts at4096.
const FULL: u16 = 256;
const CAPACITY: u16 = 2048;
const PARTIAL: u16 = 113; // deliberately ends inside the fourth name offset

pub fn win16_outline_metrics_probe_bytes() -> Result<Vec<u8>, ProbeBuildError> {
    let (code, fixups) = guest_code()?;
    build_image_with_import(&code, &fixups, 2306, b"GDI", false)
}

fn word(code: &mut CodeBuilder, prefix: &[u8], value: u16) {
    code.emit(prefix);
    code.emit(&value.to_le_bytes());
}
fn store(code: &mut CodeBuilder, offset: u16, value: u16) {
    word(code, &[0xc7, 0x06], offset);
    code.emit(&value.to_le_bytes());
}
fn require(code: &mut CodeBuilder, success: u8, status: u8, failure: &'static str) {
    // SS override makes assertion status safe even if the API clobbers DS.
    code.emit(&[success, 10, 0x36, 0xc7, 0x06, 4, 0, status, 0]);
    code.jump_near(failure);
}
fn prepare(code: &mut CodeBuilder) {
    for (opcode, value) in [(0xb8, 0x1234_a55au32), (0xba, 0x5678_5aa5),
        (0xbb, 0x9abc_1357), (0xb9, 0xabcd_2468), (0xbe, 0xbcde_369c),
        (0xbf, 0xcdef_48ad), (0xbd, 0xdef0_5abe)] {
        code.emit(&[0x66, opcode]); code.emit(&value.to_le_bytes());
    }
    code.emit(&[0x1e, 0x07, 0x89, 0x26, 12, 0, 0x8c, 0x1e, 14, 0]);
}
fn preserved(code: &mut CodeBuilder) {
    for (modrm, value, status) in [(0xfa, 0x5678_5aa5u32, 60),
        (0xfb, 0x9abc_1357, 61), (0xf9, 0xabcd_2468, 62),
        (0xfe, 0xbcde_369c, 63), (0xff, 0xcdef_48ad, 64), (0xfd, 0xdef0_5abe, 65)] {
        code.emit(&[0x66, 0x81, modrm]); code.emit(&value.to_le_bytes());
        require(code, 0x74, status, "cleanup");
    }
    code.emit(&[0x36, 0x3b, 0x26, 12, 0]);
    require(code, 0x74, 66, "cleanup");
    code.emit(&[0x8c, 0xd8, 0x36, 0x3b, 0x06, 14, 0]);
    require(code, 0x74, 67, "cleanup");
    code.emit(&[0x8c, 0xc0, 0x36, 0x3b, 0x06, 14, 0]);
    require(code, 0x74, 68, "cleanup");
}
fn compare_memory(code: &mut CodeBuilder, offset: u16, value: u16, status: u8) {
    word(code, &[0x81, 0x3e], offset); code.emit(&value.to_le_bytes());
    require(code, 0x74, status, "cleanup");
}
fn guest_code() -> Result<(Vec<u8>, Vec<[u8; 8]>), ProbeBuildError> {
    let mut code = CodeBuilder::default();
    let mut fixups = Vec::new();
    code.emit(&[0x6a, 0]);
    imported_call(&mut code, &mut fixups, 52);
    code.emit(&[0xa3, 0, 0, 0x85, 0xc0]);
    require(&mut code, 0x75, 20, "cleanup");
    code.emit(&[0x50, 0x6a, 0, 0x6a, 0, 0x0e, 0x68]);
    code.emit_offset(0, "fontproc")?;
    code.emit(&[0x6a, 0, 0x6a, 0]);
    imported_call(&mut code, &mut fixups, 330);
    code.emit(&[0x83, 0x3e, 8, 0, 0]);
    code.branch(0x75, "font_found");
    store(&mut code, 4, 77); // explicit no-TrueType skip, never success
    code.jump_near("cleanup");
    code.mark("font_found");
    // Request a modest MM_TEXT character height, independent of enumeration size.
    store(&mut code, 32, (-24i16) as u16);
    code.emit(&[0x1e, 0x6a, 32]);
    imported_call(&mut code, &mut fixups, 57);
    code.emit(&[0xa3, 2, 0, 0x85, 0xc0]);
    require(&mut code, 0x75, 21, "cleanup");
    code.emit(&[0xff, 0x36, 0, 0, 0x50]);
    imported_call(&mut code, &mut fixups, 45);
    code.emit(&[0xa3, 6, 0, 0x85, 0xc0]);
    require(&mut code, 0x75, 22, "cleanup");

    prepare(&mut code);
    code.emit(&[0xff, 0x36, 0, 0, 0x6a, 0, 0x6a, 0, 0x6a, 0]);
    imported_call(&mut code, &mut fixups, 308);
    code.emit(&[0x36, 0xa3, 10, 0]);
    code.emit(&[0x66, 0x25, 0, 0, 0xff, 0xff, 0x66, 0x3d, 0, 0, 0x34, 0x12]);
    require(&mut code, 0x74, 23, "cleanup");
    preserved(&mut code);
    code.emit(&[0xa1, 10, 0, 0x3d, 118, 0]); // header plus four terminators
    require(&mut code, 0x73, 24, "cleanup");
    word(&mut code, &[0x3d], CAPACITY);
    require(&mut code, 0x76, 25, "cleanup");
    for (offset, value) in [(126, 0x1357), (241, 0x2468), (254, 0x369c), (2304, 0x48ad)] {
        store(&mut code, offset, value);
    }
    // Fill every output byte, including unrequested tail, with a known sentinel.
    code.emit(&[0x1e, 0x07, 0xfc]);
    word(&mut code, &[0xbf], FULL); word(&mut code, &[0xb9], CAPACITY);
    code.emit(&[0xb0, 0xa5, 0xf3, 0xaa]);
    for (count, buffer) in [(PARTIAL, 128), (CAPACITY, FULL)] {
        prepare(&mut code);
        code.emit(&[0xff, 0x36, 0, 0]); word(&mut code, &[0x68], count);
        code.emit(&[0x1e]); word(&mut code, &[0x68], buffer);
        imported_call(&mut code, &mut fixups, 308);
        code.emit(&[0x66, 0x3d, 1, 0, 0x34, 0x12]); // non-NULL returns BOOL 1
        require(&mut code, 0x74, 26, "cleanup");
        preserved(&mut code);
    }
    for (offset, value, status) in [(126, 0x1357, 27), (241, 0x2468, 28),
        (254, 0x369c, 29), (2304, 0x48ad, 30)] {
        compare_memory(&mut code, offset, value, status);
    }
    // Prefix equality proves partial copying, including an odd byte at offset112.
    code.emit(&[0xbe, 128, 0, 0xbf, 0, 1, 0xb9, 113, 0, 0xfc, 0xf3, 0xa6]);
    require(&mut code, 0x74, 31, "cleanup");
    code.emit(&[0xa1, 10, 0, 0x40, 0x25, 0xfe, 0xff, 0x3b, 0x06, 0, 1]);
    require(&mut code, 0x74, 32, "cleanup"); // rounded stored size, unrounded query
    // Full buffer's unrequested tail must be unchanged, even at odd query sizes.
    code.emit(&[0x8b, 0x36, 10, 0]); word(&mut code, &[0x81, 0xc6], FULL);
    word(&mut code, &[0xb9], CAPACITY); code.emit(&[0x2b, 0x0e, 10, 0]);
    code.branch(0xe3, "tail_done");
    code.mark("tail_loop");
    code.emit(&[0x80, 0x3c, 0xa5]); require(&mut code, 0x74, 33, "cleanup");
    code.emit(&[0x46]); code.branch(0xe2, "tail_loop");
    code.mark("tail_done");
    // Read packed TEXTMETRIC16 and outline fields rather than host offsets.
    code.emit(&[0x83, 0x3e, 2, 1, 0]);
    require(&mut code, 0x7f, 41, "cleanup"); // tmHeight > 0
    code.emit(&[0xa1, 4, 1, 0x03, 0x06, 6, 1, 0x3b, 0x06, 2, 1]);
    require(&mut code, 0x74, 42, "cleanup"); // height == ascent + descent
    code.emit(&[0xf6, 0x06, 25, 1, 4]);
    require(&mut code, 0x75, 43, "cleanup"); // selected measured font is TrueType
    code.emit(&[0x83, 0x3e, 54, 1, 0]);
    require(&mut code, 0x75, 44, "cleanup"); // WORD em square at packed offset54
    compare_memory(&mut code, FULL + 106, 114, 34);
    // Four WORD offsets at106..113 are structure-relative, ordered and bounded.
    // Low-byte Unicode projection may embed a NUL; do not infer string length
    // from the first NUL or assume any installed font's name/metric numbers.
    code.emit(&[0xbf, 106, 1, 0xba, 114, 0, 0xbd, 4, 0]);
    code.mark("name_loop");
    code.emit(&[0x8b, 0x35, 0x39, 0xd6]);
    require(&mut code, 0x73, 35, "cleanup");
    code.emit(&[0x3b, 0x36, 10, 0]); require(&mut code, 0x72, 36, "cleanup");
    code.emit(&[0x89, 0xf2, 0x42, 0x8b, 0x0e, 10, 0, 0x83, 0xfd, 1]);
    code.branch(0x74, "name_bound");
    code.emit(&[0x8b, 0x4d, 2]); // next name offset bounds this name's terminator
    code.mark("name_bound");
    code.emit(&[0x3b, 0x0e, 10, 0]); require(&mut code, 0x76, 45, "cleanup");
    code.emit(&[0x39, 0xf1]); require(&mut code, 0x77, 46, "cleanup");
    code.emit(&[0x2b, 0xce]);
    word(&mut code, &[0x81, 0xc6], FULL);
    code.mark("nul_loop");
    code.emit(&[0x80, 0x3c, 0]); code.branch(0x74, "name_done");
    code.emit(&[0x46]); code.branch(0xe2, "nul_loop");
    store(&mut code, 4, 37); code.jump_near("cleanup");
    code.mark("name_done");
    code.emit(&[0x83, 0xc7, 2, 0x4d, 0x74, 3]); code.jump_near("name_loop");

    code.mark("cleanup");
    // Restore a damaged DS/SP before using owned handles during failure cleanup.
    code.emit(&[0xbc, 0, 0x10, 0x16, 0x1f]);
    code.emit(&[0x83, 0x3e, 6, 0, 0]); code.branch(0x74, "delete_font");
    code.emit(&[0xff, 0x36, 0, 0, 0xff, 0x36, 6, 0]);
    imported_call(&mut code, &mut fixups, 45);
    code.emit(&[0x3b, 0x06, 2, 0]); require(&mut code, 0x74, 38, "delete_font");
    code.mark("delete_font");
    code.emit(&[0x83, 0x3e, 2, 0, 0]); code.branch(0x74, "delete_dc");
    code.emit(&[0xff, 0x36, 2, 0]); imported_call(&mut code, &mut fixups, 69);
    code.emit(&[0x85, 0xc0]); require(&mut code, 0x75, 39, "delete_dc");
    code.mark("delete_dc");
    code.emit(&[0x83, 0x3e, 0, 0, 0]); code.branch(0x74, "exit");
    code.emit(&[0xff, 0x36, 0, 0]); imported_call(&mut code, &mut fixups, 68);
    code.emit(&[0x85, 0xc0]); require(&mut code, 0x75, 40, "exit");
    code.mark("exit");
    code.emit(&[0x83, 0x3e, 4, 0, 0]); code.branch(0x75, "skip_output");
    store(&mut code, 16, u16::from_le_bytes(*b"O1"));
    store(&mut code, 18, 0x0a0d);
    store(&mut code, 20, u16::from_le_bytes(*b"Q0"));
    store(&mut code, 22, 0x0a0d); store(&mut code, 24, 0x24);
    code.emit(&[0xf6, 0x06, 10, 0, 1]);
    code.branch(0x74, "output");
    code.emit(&[0xc6, 0x06, 21, 0, b'1']);
    code.jump_near("output");
    code.mark("skip_output");
    code.emit(&[0x83, 0x3e, 4, 0, 77]); code.branch(0x75, "terminate");
    store(&mut code, 16, u16::from_le_bytes(*b"O0"));
    store(&mut code, 18, 0x0a0d); store(&mut code, 20, 0x24);
    code.mark("output");
    code.emit(&[0xba, 16, 0, 0xb4, 9, 0xcd, 0x21]);
    code.mark("terminate");
    code.emit(&[0xa1, 4, 0, 0xb4, 0x4c, 0xcd, 0x21]);

    code.mark("fontproc");
    code.emit(&[0x55, 0x89, 0xe5, 0x1e, 0x06, 0x53, 0x56, 0x57, 0x16, 0x1f]);
    code.emit(&[0xb8, 1, 0, 0xf7, 0x46, 10, 4, 0]); // continue unless TrueType
    code.branch(0x74, "callback_return");
    code.emit(&[0xc4, 0x76, 16, 0xbf, 32, 0, 0xb9, 50, 0]);
    code.mark("copy_font");
    code.emit(&[0x26, 0x8a, 0x04, 0x88, 0x05, 0x46, 0x47]);
    code.branch(0xe2, "copy_font");
    store(&mut code, 8, 1);
    code.emit(&[0x31, 0xc0]); // stop after first TrueType
    code.mark("callback_return");
    code.emit(&[0x5f, 0x5e, 0x5b, 0x07, 0x1f, 0x5d, 0xca, 14, 0]);
    Ok((code.finish(0)?, fixups))
}

#[cfg(test)]
mod tests;
