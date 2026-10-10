//! Hidden modeless dialog lifetime acceptance through actual Win16 USER calls.
use crate::probe::{CodeBuilder, ProbeBuildError};
use crate::win16_dialog_probe::{build_image, imported_call};

/// Two CreateDialog/readback/DestroyWindow cycles, with IsWindow checked
/// immediately after each destruction, before any HWND bits can be reused.
/// LoadIcon equality checks this runtime's shared module-resource identity
/// regression, not a universal historical promise about numeric icon handles.
/// Shared/in-use icons are never destroyed. No window is shown and no input is
/// injected. Exit statuses 10..17 identify the failed assertion in each cycle.
pub fn win16_modeless_probe_bytes() -> Result<Vec<u8>, ProbeBuildError> {
    let (code, fixups) = guest_code()?;
    build_image(&code, &fixups, 12)
}

fn require(
    code: &mut CodeBuilder,
    success_opcode: u8,
    success_label: &'static str,
    status: u8,
) {
    code.branch(success_opcode, success_label);
    code.emit(&[0xc7, 0x06, 4, 0, status, 0]); // mov word [failure],status
    code.jump_near("cleanup");
    code.mark(success_label);
}

fn load_resource_icon(code: &mut CodeBuilder, fixups: &mut Vec<[u8; 8]>) {
    code.emit(&[0xff, 0x36, 0, 0, 0x6a, 0, 0x6a, 7]); // saved instance, resource7
    imported_call(code, fixups, 174);
}

fn guest_code() -> Result<(Vec<u8>, Vec<[u8; 8]>), ProbeBuildError> {
    let mut code = CodeBuilder::default();
    let mut fixups = Vec::new();
    // DGROUP words: instance0, init_count2, failure4, dialog6, icon8, expected10.
    code.emit(&[0x89, 0x3e, 0, 0, 0xc7, 0x06, 10, 0, 1, 0]);
    code.mark("cycle");
    code.emit(&[0xff, 0x36, 0, 0, 0x6a, 0, 0x6a, 1, 0x6a, 0, 0x0e, 0x68]);
    code.emit_offset(0, "dlgproc")?;
    imported_call(&mut code, &mut fixups, 89); // CreateDialog(instance,1,0,CS:dlgproc)
    code.emit(&[0xa3, 6, 0, 0x85, 0xc0]);
    require(&mut code, 0x75, "created", 10);
    code.emit(&[0xa1, 2, 0, 0x3b, 0x06, 10, 0]);
    require(&mut code, 0x74, "initialized", 11); // exactly one init per creation
    code.emit(&[0xff, 0x36, 6, 0, 0x6a, 10]);
    imported_call(&mut code, &mut fixups, 91);
    code.emit(&[0x85, 0xc0]);
    require(&mut code, 0x75, "child", 12);
    code.emit(&[0x50, 0x68, 1, 4, 0x6a, 0, 0x6a, 0, 0x6a, 0]);
    imported_call(&mut code, &mut fixups, 111); // Win16 STM_GETICON=0401
    code.emit(&[0x85, 0xc0]);
    require(&mut code, 0x75, "icon", 13);
    code.emit(&[0xa3, 8, 0]);
    load_resource_icon(&mut code, &mut fixups);
    code.emit(&[0x3b, 0x06, 8, 0]);
    require(&mut code, 0x74, "shared_icon", 14);
    code.emit(&[0xff, 0x36, 6, 0]);
    imported_call(&mut code, &mut fixups, 53); // DestroyWindow, never EndDialog
    code.emit(&[0x85, 0xc0]);
    require(&mut code, 0x75, "destroyed", 15);
    code.emit(&[0xff, 0x36, 6, 0]);
    imported_call(&mut code, &mut fixups, 47); // IsWindow immediately, before recreation
    code.emit(&[0x85, 0xc0]);
    require(&mut code, 0x74, "retired", 16);
    code.emit(&[0xc7, 0x06, 6, 0, 0, 0]); // no live dialog remains to clean up
    load_resource_icon(&mut code, &mut fixups);
    code.emit(&[0x3b, 0x06, 8, 0]);
    require(&mut code, 0x74, "resource_survived", 17);
    code.emit(&[0xff, 0x06, 10, 0, 0x83, 0x3e, 10, 0, 3]);
    code.branch(0x74, "finished");
    code.jump_near("cycle");
    code.mark("finished");
    code.emit(&[0xb8, 0, 0x4c, 0xcd, 0x21]);

    code.mark("cleanup");
    code.emit(&[0x83, 0x3e, 6, 0, 0]);
    code.branch(0x74, "exit_failure");
    code.emit(&[0xff, 0x36, 6, 0]);
    imported_call(&mut code, &mut fixups, 53); // best effort only on failure
    code.mark("exit_failure");
    code.emit(&[0xa1, 4, 0, 0xb4, 0x4c, 0xcd, 0x21]);

    code.mark("dlgproc");
    code.emit(&[0x55, 0x89, 0xe5, 0x1e, 0x06, 0x53, 0x56, 0x57, 0x16, 0x1f]);
    code.emit(&[0x31, 0xc0, 0x81, 0x7e, 12, 0x10, 1]);
    code.branch(0x75, "return");
    code.emit(&[0xff, 0x06, 2, 0, 0xb8, 1, 0]);
    code.mark("return");
    code.emit(&[0x5f, 0x5e, 0x5b, 0x07, 0x1f, 0x5d, 0xca, 10, 0]);
    Ok((code.finish(0)?, fixups))
}

#[cfg(test)]
mod tests;
