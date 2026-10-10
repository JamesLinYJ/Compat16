//! Repository-authored native font-family acceptance, without installed fixtures.
use crate::probe::{CodeBuilder, ProbeBuildError};
use crate::win16_dialog_probe::{build_image_with_import, imported_call};

/// Discover a family on the native memory DC, then enumerate that family. Both
/// callbacks deliberately stop at their first record. Exit zero requires real
/// callback execution, bounded strings, packed records, LPARAM fidelity, and
/// restored Pascal caller state. No font name or installed-font count is fixed.
pub fn win16_font_families_probe_bytes() -> Result<Vec<u8>, ProbeBuildError> {
    let (code, fixups) = guest_code()?;
    build_image_with_import(&code, &fixups, 84, b"GDI", false)
}

fn require(code: &mut CodeBuilder, success: u8, status: u8, failure: &'static str) {
    // A short successful branch skips the failure store and a near jump.
    code.emit(&[success, 9, 0xc7, 0x06, 4, 0, status, 0]);
    code.jump_near(failure);
}

fn guest_code() -> Result<(Vec<u8>, Vec<[u8; 8]>), ProbeBuildError> {
    let mut code = CodeBuilder::default();
    let mut fixups = Vec::new();
    // DGROUP: count0, DC2, failure4, savedSP6, phase8, face10[32], metric42[41].
    code.emit(&[0x6a, 0]);
    imported_call(&mut code, &mut fixups, 52); // CreateCompatibleDC(NULL)
    code.emit(&[0xa3, 2, 0, 0x85, 0xc0]);
    require(&mut code, 0x75, 20, "cleanup");
    code.emit(&[0xbb, 0x57, 0x13, 0xbe, 0x68, 0x24, 0xbf, 0x9c, 0x36, 0xbd, 0xbc, 0x4a]);
    code.emit(&[0x1e, 0x07, 0x89, 0x26, 6, 0]); // ES=DS, save SP
    code.mark("enumerate");
    code.emit(&[0xff, 0x36, 2, 0, 0x83, 0x3e, 8, 0, 0]);
    code.branch(0x75, "named");
    code.emit(&[0x6a, 0, 0x6a, 0]); // NULL family pointer
    code.branch(0xeb, "arguments");
    code.mark("named");
    code.emit(&[0x1e, 0x6a, 10]); // family copied into this guest's own DS
    code.mark("arguments");
    code.emit(&[0x0e, 0x68]);
    code.emit_offset(0, "fontproc")?;
    code.emit(&[0x68, 0x5e, 0xa1, 0x68, 0xcd, 0x42]); // magic LPARAM a15e42cd
    imported_call(&mut code, &mut fixups, 330); // 14-byte Pascal API arguments
    code.emit(&[0x85, 0xc0]);
    require(&mut code, 0x74, 21, "cleanup"); // stop result is exactly AX=0
    code.emit(&[0x3b, 0x26, 6, 0]);
    require(&mut code, 0x74, 22, "cleanup");
    code.emit(&[0x81, 0xfb, 0x57, 0x13]);
    require(&mut code, 0x74, 23, "cleanup");
    code.emit(&[0x81, 0xfe, 0x68, 0x24]);
    require(&mut code, 0x74, 24, "cleanup");
    code.emit(&[0x81, 0xff, 0x9c, 0x36]);
    require(&mut code, 0x74, 25, "cleanup");
    code.emit(&[0x81, 0xfd, 0xbc, 0x4a]);
    require(&mut code, 0x74, 26, "cleanup");
    code.emit(&[0x8c, 0xc0, 0x8c, 0xda, 0x39, 0xd0]); // ES == DS
    require(&mut code, 0x74, 27, "cleanup");
    code.emit(&[0x83, 0x3e, 4, 0, 0]);
    code.branch(0x75, "cleanup"); // retain the callback's specific failure
    code.emit(&[0xa1, 8, 0, 0x40, 0x3b, 0x06, 0, 0]);
    require(&mut code, 0x74, 28, "cleanup"); // exactly one callback per API call
    code.emit(&[0xff, 0x06, 8, 0, 0x83, 0x3e, 8, 0, 2]);
    code.branch(0x74, "cleanup");
    code.jump_near("enumerate");
    code.mark("cleanup");
    code.emit(&[0x83, 0x3e, 2, 0, 0]);
    code.branch(0x74, "exit");
    code.emit(&[0xff, 0x36, 2, 0]);
    imported_call(&mut code, &mut fixups, 68); // DeleteDC, including assertion failures
    code.emit(&[0x85, 0xc0]);
    code.branch(0x75, "exit");
    code.emit(&[0xc7, 0x06, 4, 0, 29, 0]);
    code.mark("exit");
    code.emit(&[0xa1, 4, 0, 0xb4, 0x4c, 0xcd, 0x21]);

    code.mark("fontproc");
    code.emit(&[0x55, 0x89, 0xe5, 0x1e, 0x06, 0x53, 0x56, 0x57, 0x16, 0x1f]);
    // BP+6/+8 LPARAM, +10 font type, +12/+14 metric, +16/+18 font.
    code.emit(&[0xff, 0x06, 0, 0, 0x81, 0x7e, 6, 0xcd, 0x42]);
    require(&mut code, 0x74, 30, "return");
    code.emit(&[0x81, 0x7e, 8, 0x5e, 0xa1]);
    require(&mut code, 0x74, 31, "return");
    code.emit(&[0xc4, 0x76, 16, 0x83, 0xc6, 18, 0xbf, 10, 0, 0xb9, 32, 0]);
    code.emit(&[0x26, 0x80, 0x3c, 0]); // nonempty face name
    require(&mut code, 0x75, 32, "return");
    code.mark("face_loop");
    code.emit(&[0x26, 0x8a, 0x04, 0x83, 0x3e, 8, 0, 0]);
    code.branch(0x74, "copy_face");
    code.emit(&[0x3a, 0x05]); // named enumeration must return the requested family
    require(&mut code, 0x74, 33, "return");
    code.mark("copy_face");
    code.emit(&[0x88, 0x05, 0x46, 0x47, 0x84, 0xc0]);
    code.branch(0x74, "face_done");
    code.branch(0xe2, "face_loop");
    code.emit(&[0xc7, 0x06, 4, 0, 34, 0]); // no NUL within 32 bytes
    code.jump_near("return");
    code.mark("face_done");
    // The runtime's family record is 146 bytes, followed by packed metrics (41 bytes for TrueType).
    // Verify the actual callback pointers, not only static generator metadata.
    code.emit(&[0x8b, 0x46, 18, 0x3b, 0x46, 14]);
    require(&mut code, 0x74, 35, "return");
    code.emit(&[0x8b, 0x46, 16, 0x05, 146, 0, 0x3b, 0x46, 12]);
    require(&mut code, 0x74, 36, "return");
    code.emit(&[0xc4, 0x76, 16, 0x83, 0xc6, 50, 0xb9, 64, 0]);
    // Full/style may be empty; only their fixed NUL-terminated bounds matter.
    code.mark("full_loop");
    code.emit(&[0x26, 0x80, 0x3c, 0]);
    code.branch(0x74, "full_done");
    code.emit(&[0x46]);
    code.branch(0xe2, "full_loop");
    code.emit(&[0xc7, 0x06, 4, 0, 37, 0]);
    code.jump_near("return");
    code.mark("full_done");
    code.emit(&[0xc4, 0x76, 16, 0x83, 0xc6, 114, 0xb9, 32, 0]);
    code.mark("style_loop");
    code.emit(&[0x26, 0x80, 0x3c, 0]);
    code.branch(0x74, "style_done");
    code.emit(&[0x46]);
    code.branch(0xe2, "style_loop");
    code.emit(&[0xc7, 0x06, 4, 0, 38, 0]);
    code.jump_near("return");
    code.mark("style_done");
    // Only TrueType promises the NEWTEXTMETRIC extension; other fonts provide
    // the 31-byte TEXTMETRIC base. Do not inspect their padded extension.
    code.emit(&[0xc4, 0x76, 12, 0xbf, 42, 0, 0xb9, 31, 0]);
    code.emit(&[0xf7, 0x46, 10, 4, 0]); // TRUETYPE_FONTTYPE
    code.branch(0x74, "metric_loop");
    code.emit(&[0x83, 0xc1, 10]);
    code.mark("metric_loop");
    code.emit(&[0x26, 0x8a, 0x04, 0x88, 0x05, 0x46, 0x47]);
    code.branch(0xe2, "metric_loop"); // copy valid packed bytes to owned DGROUP
    code.emit(&[0x83, 0x3e, 42, 0, 0]); // tmHeight > 0 on this native font DC
    require(&mut code, 0x7f, 39, "return");
    code.emit(&[0xf7, 0x46, 10, 4, 0]);
    code.branch(0x74, "return"); // raster/vector extended fields have no such guarantee
    code.emit(&[0x83, 0x3e, 77, 0, 0]); // ntmSizeEM WORD at metric+35
    require(&mut code, 0x75, 40, "return");
    code.mark("return");
    code.emit(&[0x31, 0xc0, 0x5f, 0x5e, 0x5b, 0x07, 0x1f, 0x5d, 0xca, 14, 0]);
    Ok((code.finish(0)?, fixups))
}

#[cfg(test)]
mod tests;
