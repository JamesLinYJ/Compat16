//! An NE program proves GlobalNotify without host-side callback substitution.
use super::{Code, ne};

fn push_handle(code: &mut Code) {
    code.emit(&[0xff, 0x36]);
    code.word(16);
}

fn discard(code: &mut Code) {
    push_handle(code);
    code.immediate(0x68, 0);
    code.immediate(0x68, 0);
    code.immediate(0x68, 2);
    code.call(16); // GlobalReAlloc(handle, 0, GMEM_MOVEABLE).
}

fn compare(code: &mut Code, value: u16) {
    code.immediate(0x3d, value);
    code.fail_if(0x85);
}

fn flags(code: &mut Code, discarded: bool) {
    push_handle(code);
    code.call(22);
    code.immediate(0x25, 0x4000);
    compare(code, if discarded { 0x4000 } else { 0 });
}

pub fn global_notify_program() -> Vec<u8> {
    let data = vec![0; 512];
    let mut code = Code::default();
    code.immediate(0x68, 0x4102); // MOVEABLE | DISCARDABLE | NOTIFY.
    code.immediate(0x68, 0);
    code.immediate(0x68, 64);
    code.call(15);
    code.immediate(0x3d, 32);
    code.fail_if(0x82);
    code.immediate(0xa3, 16);
    flags(&mut code, false); // Input NOTIFY is not output DISCARDED.

    code.emit(&[0x0e, 0x68]); // Push CS and the callback's offset.
    let callback_site = code.bytes.len();
    code.word(0);
    code.immediate(0xb8, 0xa55a);
    code.immediate(0xba, 0x5aa5);
    code.call(154);
    compare(&mut code, 0xa55a); // VOID preserves AX/DX.
    code.emit(&[0x81, 0xfa]);
    code.word(0x5aa5);
    code.fail_if(0x85);

    discard(&mut code); // The first callback returns FALSE.
    compare(&mut code, 0);
    flags(&mut code, false);
    code.emit(&[0xc7, 0x06]);
    code.word(18);
    code.word(1);
    discard(&mut code); // The second callback returns TRUE.
    code.emit(&[0x3b, 0x06]);
    code.word(16);
    code.fail_if(0x85);
    flags(&mut code, true);
    code.immediate(0xa1, 20);
    compare(&mut code, 2);
    code.immediate(0xa1, 22);
    code.emit(&[0x3b, 0x06]);
    code.word(16);
    code.fail_if(0x85);
    code.immediate(0x68, 1);
    code.call(126); // MemoryFreed outside a callback has no active budget.
    compare(&mut code, 0);
    code.emit(&[0x0b, 0xd2]);
    code.fail_if(0x85);
    code.immediate(0x68, 0);
    code.immediate(0x68, 0);
    code.call(154); // Unregister, then restore and discard the same HGLOBAL.
    push_handle(&mut code);
    code.immediate(0x68, 0);
    code.immediate(0x68, 64);
    code.immediate(0x68, 2);
    code.call(16);
    code.emit(&[0x3b, 0x06]);
    code.word(16);
    code.fail_if(0x85);
    discard(&mut code);
    flags(&mut code, true);
    code.immediate(0xa1, 20);
    compare(&mut code, 2); // Clearing registration prevents a third callback.
    code.interrupt(0x4c00);

    let callback = code.bytes.len() as u16;
    code.bytes[callback_site..callback_site + 2].copy_from_slice(&callback.to_le_bytes());
    code.emit(&[0x55, 0x8b, 0xec, 0x8c, 0xd3, 0x3b, 0xc3]); // BP frame; AX == SS.
    code.fail_if(0x85);
    code.emit(&[0x8c, 0xdb, 0x3b, 0xc3]); // DS == SS.
    code.fail_if(0x85);
    code.emit(&[0x8c, 0xc3, 0x3b, 0xc3]); // ES == SS.
    code.fail_if(0x85);
    code.emit(&[0x8b, 0x5e, 6, 0x89, 0x1e]); // The sole HGLOBAL argument.
    code.word(22);
    code.emit(&[0xff, 0x06]);
    code.word(20);
    code.immediate(0x68, 0);
    code.call(126); // A nested API must preserve the active FAR callback.
    compare(&mut code, 0);
    code.emit(&[0x0b, 0xd2]);
    code.fail_if(0x85);
    code.immediate(0xa1, 18);
    code.emit(&[0x5d, 0xca, 2, 0]); // BOOL result and Pascal RETF 2.
    ne("GNOTIFY", &code.finish(), &data, &["KERNEL"], false)
}
