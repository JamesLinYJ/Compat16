//! Real NE imports exercise the LocalHandleDelta policy through the guest ABI.
//! The explicit small heap is below the stack and cannot grow into DGROUP's tail.
use crate::probe::{CodeBuilder, ProbeBuildError};
use crate::win16_dialog_probe::{build_image_with_import, imported_call};

const STATUS: u16 = 32;
const SAVED_SP: u16 = 34;
const SAVED_DS: u16 = 36;
const HANDLES: [u16; 3] = [40, 42, 44];
const LOCKED: u16 = 46;
const HEAP_START: u16 = 0x200;
const HEAP_END: u16 = 0x2ef;
const DATA_LENGTH: usize = 0x2f2;

pub fn win16_local_handle_delta_probe_bytes() -> Result<Vec<u8>, ProbeBuildError> {
    let (code, fixups) = guest_code()?;
    build_image_with_import(&code, &fixups, DATA_LENGTH, b"KERNEL", false)
}

fn word(code: &mut CodeBuilder, prefix: &[u8], value: u16) {
    code.emit(prefix);
    code.emit_word(value);
}
fn store(code: &mut CodeBuilder, offset: u16, value: u16) {
    word(code, &[0xc7, 0x06], offset);
    code.emit_word(value);
}
fn require(code: &mut CodeBuilder, success: u8, status: u8, failure: &'static str) {
    // SS remains the owned stack segment even when an API corrupts DS.
    code.emit(&[success, 10, 0x36, 0xc7, 0x06, STATUS as u8, 0, status, 0]);
    code.jump_near(failure);
}
fn preserved(code: &mut CodeBuilder, failure: &'static str) {
    word(code, &[0x36, 0x3b, 0x26], SAVED_SP); // cmp sp, ss:[saved_sp]
    require(code, 0x74, 60, failure);
    code.emit(&[0x8c, 0xd9]); // mov cx, ds (leave AX result intact)
    word(code, &[0x36, 0x3b, 0x0e], SAVED_DS);
    require(code, 0x74, 61, failure);
}
fn call(code: &mut CodeBuilder, fixups: &mut Vec<[u8; 8]>, ordinal: u16) {
    imported_call(code, fixups, ordinal);
    preserved(code, "cleanup");
}
fn delta(code: &mut CodeBuilder, fixups: &mut Vec<[u8; 8]>, value: u16, expected: u16, status: u8) {
    // ret16 must preserve EAX's upper word as well as Pascal's two-byte cleanup.
    code.emit(&[0x66, 0xb8, 0x5a, 0xa5, 0x34, 0x12]);
    word(code, &[0x68], value);
    call(code, fixups, 310);
    code.emit(&[0x66, 0x3d]);
    code.emit(&(0x1234_0000u32 | u32::from(expected)).to_le_bytes());
    require(code, 0x74, status, "cleanup");
}
fn compare(code: &mut CodeBuilder, offset: u16, value: u16, status: u8, failure: &'static str) {
    word(code, &[0x81, 0x3e], offset);
    code.emit_word(value);
    require(code, 0x74, status, failure);
}
fn alloc(code: &mut CodeBuilder, fixups: &mut Vec<[u8; 8]>, size: u16, slot: u16, status: u8) {
    code.emit(&[0x6a, 0x12]); // LMEM_MOVEABLE | LMEM_NOCOMPACT
    word(code, &[0x68], size);
    imported_call(code, fixups, 5);
    word(code, &[0x36, 0xa3], slot); // retain ownership before ABI assertions
    preserved(code, "cleanup");
    code.emit(&[0x85, 0xc0]);
    require(code, 0x75, status, "cleanup");
}
fn restore(code: &mut CodeBuilder) {
    code.emit(&[0xbc, 0, 0x10, 0x16, 0x1f]); // SP=4096; DS=SS
}
fn guest_code() -> Result<(Vec<u8>, Vec<[u8; 8]>), ProbeBuildError> {
    let mut code = CodeBuilder::default();
    let mut fixups = Vec::new();
    word(&mut code, &[0x89, 0x26], SAVED_SP);
    word(&mut code, &[0x8c, 0x1e], SAVED_DS);
    store(&mut code, HEAP_START - 2, 0x1357);
    store(&mut code, HEAP_END + 1, 0x2468);
    code.emit(&[0x6a, 0]); // LocalInit(0, start, inclusive_end): caller DS
    word(&mut code, &[0x68], HEAP_START);
    word(&mut code, &[0x68], HEAP_END);
    call(&mut code, &mut fixups, 4);
    code.emit(&[0x85, 0xc0]);
    require(&mut code, 0x75, 20, "cleanup");
    delta(&mut code, &mut fixups, 0, 32, 21);
    // Default 32-entry table and 96-byte payload cannot coexist in this heap.
    code.emit(&[0x6a, 0x12, 0x6a, 96]);
    imported_call(&mut code, &mut fixups, 5);
    word(&mut code, &[0x36, 0xa3], HANDLES[0]);
    preserved(&mut code, "cleanup");
    code.emit(&[0x85, 0xc0]);
    require(&mut code, 0x74, 22, "cleanup");
    delta(&mut code, &mut fixups, 1, 1, 23);
    delta(&mut code, &mut fixups, 0, 1, 24);
    alloc(&mut code, &mut fixups, 96, HANDLES[0], 25);
    word(&mut code, &[0xff, 0x36], HANDLES[0]);
    imported_call(&mut code, &mut fixups, 8);
    // A successful lock is owned before any assertion can transfer to cleanup.
    word(&mut code, &[0x36, 0xa3], LOCKED);
    preserved(&mut code, "cleanup");
    code.emit(&[0x85, 0xc0]);
    require(&mut code, 0x75, 26, "cleanup");
    word(&mut code, &[0x3d], HEAP_START);
    require(&mut code, 0x73, 27, "cleanup");
    word(&mut code, &[0x3d], HEAP_END - 95);
    require(&mut code, 0x76, 28, "cleanup");
    code.emit(&[0x89, 0xc3, 0xc7, 0x07, 0x5a, 0xa5, 0xc7, 0x47, 94, 0xa5, 0x5a]);
    delta(&mut code, &mut fixups, 2, 2, 29);
    delta(&mut code, &mut fixups, 0, 2, 30);
    // Two discarded (zero-size) movable handles force a later table expansion.
    alloc(&mut code, &mut fixups, 0, HANDLES[1], 31);
    alloc(&mut code, &mut fixups, 0, HANDLES[2], 32);
    for (left, right) in [(0, 1), (0, 2), (1, 2)] {
        word(&mut code, &[0xa1], HANDLES[left]);
        word(&mut code, &[0x3b, 0x06], HANDLES[right]);
        require(&mut code, 0x75, 33, "cleanup");
    }
    word(&mut code, &[0x8b, 0x1e], LOCKED);
    code.emit(&[0x81, 0x3f, 0x5a, 0xa5]);
    require(&mut code, 0x74, 34, "cleanup");
    code.emit(&[0x81, 0x7f, 94, 0xa5, 0x5a]);
    require(&mut code, 0x74, 35, "cleanup");

    code.mark("cleanup");
    restore(&mut code);
    word(&mut code, &[0x83, 0x3e], LOCKED); code.emit(&[0]);
    code.branch(0x74, "free_third");
    word(&mut code, &[0xff, 0x36], HANDLES[0]);
    imported_call(&mut code, &mut fixups, 9);
    preserved(&mut code, "free_third");
    code.emit(&[0x85, 0xc0]); // final unlock returns zero, not a success BOOL
    require(&mut code, 0x74, 36, "free_third");
    for (slot, label, next) in [(HANDLES[2], "free_third", "free_second"),
        (HANDLES[1], "free_second", "free_first"), (HANDLES[0], "free_first", "canaries")] {
        code.mark(label);
        restore(&mut code);
        word(&mut code, &[0x83, 0x3e], slot); code.emit(&[0]);
        code.branch(0x74, next);
        word(&mut code, &[0xff, 0x36], slot);
        imported_call(&mut code, &mut fixups, 7);
        preserved(&mut code, next);
        code.emit(&[0x85, 0xc0]); // zero is successful free; nonzero retains handle
        require(&mut code, 0x74, 37, next);
    }
    code.mark("canaries");
    restore(&mut code);
    compare(&mut code, HEAP_START - 2, 0x1357, 38, "exit");
    compare(&mut code, HEAP_END + 1, 0x2468, 39, "exit");
    code.mark("exit");
    word(&mut code, &[0x83, 0x3e], STATUS); code.emit(&[0]);
    code.branch(0x75, "terminate");
    store(&mut code, 48, u16::from_le_bytes(*b"L1"));
    store(&mut code, 50, 0x0a0d); store(&mut code, 52, 0x24);
    code.emit(&[0xba, 48, 0, 0xb4, 9, 0xcd, 0x21]);
    code.mark("terminate");
    word(&mut code, &[0xa1], STATUS);
    code.emit(&[0xb4, 0x4c, 0xcd, 0x21]);
    Ok((code.finish(0)?, fixups))
}

#[cfg(test)]
mod tests;
