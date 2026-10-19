//! Read-only default settings through COMMDLG, GDI and the printer worker.
use super::{Code, ne};
use win16_abi::commdlg_abi::PrintDlg16;

fn call(code: &mut Code, module: u16, ordinal: u16) {
    code.emit(&[0x9a]);
    code.imports
        .push((code.bytes.len() as u16, module, ordinal));
    code.emit(&[0; 4]);
}

fn push_word(code: &mut Code, offset: u16) {
    code.emit(&[0xff, 0x36]);
    code.word(offset);
}

fn push_mode(code: &mut Code) {
    push_word(code, 66); // Copied, checked GlobalLock selector and offset.
    push_word(code, 64);
}

fn push_name(code: &mut Code, member: u8) {
    // DEVNAMES offsets are byte offsets from the beginning of the locked block.
    // Reload ES:BX after each native call, preserving the program's DS.
    code.emit(&[0x8e, 0x06]);
    code.word(70);
    code.emit(&[0x8b, 0x1e]);
    code.word(68);
    code.emit(&[0x26, 0x8b, 0x47, member, 0x03, 0xc3]); // AX=ES:[BX+member]+BX.
    push_word(code, 70);
    code.emit(&[0x50]);
}

pub fn default_printer_round_trip_program() -> Vec<u8> {
    printer_program(false)
}

pub fn ext_device_mode_round_trip_program() -> Vec<u8> {
    printer_program(true)
}

fn printer_program(ext_device_mode: bool) -> Vec<u8> {
    let mut data = vec![0; 512];
    let dialog = PrintDlg16 {
        structure_size: PrintDlg16::SIZE as u32,
        flags: 0x0400, // PD_RETURNDEFAULT: no dialog, update, or print job.
        copies: 1,
        ..Default::default()
    };
    data[..PrintDlg16::SIZE].copy_from_slice(&dialog.encode());
    let mut code = Code::default();
    code.emit(&[0x1e]);
    code.immediate(0x68, 0);
    call(&mut code, 2, 20); // COMMDLG.PrintDlg.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    for (handle, pointer) in [(6, 64), (8, 68)] {
        push_word(&mut code, handle);
        code.call(18); // KERNEL.GlobalLock.
        code.emit(&[0x0b, 0xd2]);
        code.fail_if(0x84);
        code.immediate(0xa3, pointer);
        code.emit(&[0x89, 0x16]);
        code.word(pointer + 2);
    }
    if ext_device_mode {
        initialize_ext_device_mode(&mut code);
    }
    code.emit(&[0x8e, 0x06]);
    code.word(66);
    code.emit(&[0x8b, 0x1e]);
    code.word(64);
    code.emit(&[0x26, 0x83, 0x7f, 36, 68]); // Win3.1 dmSize.
    code.fail_if(0x85);
    code.emit(&[0x26, 0x83, 0x7f, 38, 100]); // At least modern public bytes + trailer.
    code.fail_if(0x82);
    push_name(&mut code, 0);
    push_name(&mut code, 2);
    push_name(&mut code, 4);
    push_mode(&mut code);
    call(&mut code, 3, 153); // GDI.CreateIC consumes the returned settings.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.emit(&[0x50]);
    call(&mut code, 3, 68); // DeleteDC, without any print lifecycle operation.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    for (index, expected) in [(8, Some(68)), (9, None), (10, Some(0x030a))] {
        push_name(&mut code, 2);
        push_name(&mut code, 4);
        code.immediate(0x68, index);
        code.immediate(0x68, 0);
        code.immediate(0x68, 0); // NULL output for the scalar query.
        push_mode(&mut code);
        call(&mut code, 4, 91); // WINSPOOL.DeviceCapabilities, isolated worker.
        code.emit(&[0x0b, 0xd2]);
        code.fail_if(0x85); // Positive scalar WORD sizes/spec, never -1.
        if let Some(expected) = expected {
            code.immediate(0x3d, expected);
            code.fail_if(0x85);
        } else {
            code.immediate(0x3d, 100);
            code.fail_if(0x82);
        }
    }
    for handle in [6, 8].into_iter().chain(ext_device_mode.then_some(82)) {
        push_word(&mut code, handle);
        code.call(19); // KERNEL.GlobalUnlock.
        push_word(&mut code, handle);
        code.call(17); // KERNEL.GlobalFree.
        code.emit(&[0x0b, 0xc0]);
        code.fail_if(0x85);
    }
    ne(
        "PRNMODE",
        &code.finish(),
        &data,
        &["KERNEL", "COMMDLG", "GDI", "WINSPOOL"],
        false,
    )
}

#[derive(Clone, Copy)]
enum ModePointer {
    Null,
    ReturnedMode,
    Invalid,
}

fn push_mode_argument(code: &mut Code, pointer: ModePointer) {
    match pointer {
        ModePointer::ReturnedMode => push_mode(code),
        ModePointer::Null | ModePointer::Invalid => {
            code.immediate(
                0x68,
                if matches!(pointer, ModePointer::Invalid) {
                    0xffff
                } else {
                    0
                },
            );
            code.immediate(0x68, 0);
        }
    }
}

fn ext_call(code: &mut Code, flags: u16, output: ModePointer, input: ModePointer) {
    code.immediate(0x68, 0); // No owner for these noninteractive operations.
    code.immediate(0x68, 0x1234); // Original hInst is unused, not a native handle.
    push_mode_argument(code, output);
    push_name(code, 2);
    push_name(code, 4);
    push_mode_argument(code, input);
    code.immediate(0x68, 0);
    code.immediate(0x68, 0); // Unused profile.
    code.immediate(0x68, flags);
    call(code, 4, 90);
}

fn initialize_ext_device_mode(code: &mut Code) {
    use ModePointer::{Invalid, Null, ReturnedMode};
    ext_call(code, 0, Null, Invalid); // An unused input address is not touched.
    code.immediate(0x3d, 0xffff);
    code.fail_if(0x84);
    code.immediate(0x3d, 168);
    code.fail_if(0x82);
    code.immediate(0xa3, 80); // Checked query size.
    ext_call(code, 2, Null, Null); // DM_COPY + NULL output is another size query.
    code.emit(&[0x3b, 0x06]);
    code.word(80);
    code.fail_if(0x85);
    code.immediate(0x68, 0x42); // GMEM_MOVEABLE | GMEM_ZEROINIT.
    code.immediate(0x68, 0);
    code.emit(&[0x50]); // DWORD allocation size from the WORD query.
    code.call(15); // GlobalAlloc.
    code.emit(&[0x0b, 0xc0]);
    code.fail_if(0x84);
    code.immediate(0xa3, 82);
    code.emit(&[0x50]);
    code.call(18); // GlobalLock into the shared mode FAR slots.
    code.emit(&[0x0b, 0xd2]);
    code.fail_if(0x84);
    code.immediate(0xa3, 64);
    code.emit(&[0x89, 0x16]);
    code.word(66);
    ext_call(code, 2, ReturnedMode, Null);
    code.immediate(0x3d, 1);
    code.fail_if(0x85);
    for (flags, output, input) in [(8, Null, Invalid), (2, Invalid, Null)] {
        ext_call(code, flags, output, input);
        code.immediate(0x3d, 0xffff);
        code.fail_if(0x85); // Immediate failure must restore the real caller too.
    }
    code.emit(&[0x8e, 0x06]);
    code.word(66);
    code.emit(&[0x8b, 0x1e]);
    code.word(64);
    // Change only orientation; leave other public/private values to the driver.
    for (offset, value) in [(40, 1), (42, 0), (44, 2)] {
        code.emit(&[0x26, 0xc7, 0x47, offset]);
        code.word(value);
    }
    ext_call(code, 10, ReturnedMode, ReturnedMode); // DM_MODIFY | DM_COPY, same FAR.
    code.immediate(0x3d, 1);
    code.fail_if(0x85);
    code.emit(&[0x8e, 0x06]);
    code.word(66);
    code.emit(&[0x8b, 0x1e]);
    code.word(64);
    code.emit(&[0x26, 0x83, 0x7f, 44, 2]); // Driver accepted landscape.
    code.fail_if(0x85);
}
