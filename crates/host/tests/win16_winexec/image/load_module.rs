//! Original NE entry points exercise the public KERNEL loader ABI.

use super::{Code, ne, ne_with_exports, put};

pub struct ModuleLaunch<'a> {
    pub name: &'a [u8],
    pub tail: &'a [u8],
    pub show: u16,
    pub environment: Option<&'a [u8]>,
    pub expected_error: Option<u16>,
}

impl Code {
    fn push_at(&mut self, offset: u16) {
        self.emit(&[0xff, 0x36]);
        self.word(offset);
    }
    fn compare(&mut self, value: u16) {
        self.immediate(0x3d, value);
        self.fail_if(0x85);
    }
    fn branch(&mut self, condition: u8, target: usize) {
        self.emit(&[0x0f, condition]);
        let relative = i16::try_from(target as isize - (self.bytes.len() + 2) as isize).unwrap();
        self.word(relative as u16);
    }
    fn close(&mut self) {
        self.interrupt(0x3e00);
        self.fail_if(0x82);
    }
    fn create(&mut self, name: u16) {
        self.immediate(0xba, name);
        self.immediate(0xb9, 0);
        self.interrupt(0x3c00);
        self.fail_if(0x82);
        self.emit(&[0x89, 0xc3]);
    }
    fn record(&mut self, name: u16, buffer: u16, length: u16) {
        self.create(name);
        self.immediate(0xba, buffer);
        self.immediate(0xb9, length);
        self.interrupt(0x4000);
        self.fail_if(0x82);
        self.close();
    }
    fn library_return(&mut self, cleanup: u16) {
        self.immediate(0xb8, 1);
        if cleanup == 0 {
            self.emit(&[0xcb]);
        } else {
            self.emit(&[0xca]);
            self.word(cleanup);
        }
        let failure = self.bytes.len();
        self.immediate(0xb8, 0);
        if cleanup == 0 {
            self.emit(&[0xcb]);
        } else {
            self.emit(&[0xca]);
            self.word(cleanup);
        }
        for site in self.failures.drain(..) {
            let relative = i16::try_from(failure as isize - (site + 2) as isize).unwrap();
            self.bytes[site..site + 2].copy_from_slice(&relative.to_le_bytes());
        }
    }
    fn module_by_name(&mut self, offset: u16, parameters: u32) {
        self.emit(&[0x1e]);
        self.immediate(0x68, offset);
        self.immediate(0x68, (parameters >> 16) as u16);
        self.immediate(0x68, parameters as u16);
        self.call(45);
    }
    fn module_usage(&mut self, handle: u16, expected: u16) {
        self.push_at(handle);
        self.call(48);
        self.compare(expected);
    }
    fn release_module(&mut self, handle: u16, expected: u16) {
        self.push_at(handle);
        self.call(46);
        self.compare(expected);
    }
}

pub fn module_parent(case: ModuleLaunch<'_>) -> Vec<u8> {
    let mut data = vec![0; 1024];
    data[..8].copy_from_slice(b"..\\WORK\0");
    data[16..27].copy_from_slice(b"RESULT.OUT\0");
    data[32..43].copy_from_slice(b"MODULE.OUT\0");
    data[48..59].copy_from_slice(b"RELEASE.OK\0");
    data[64..64 + case.name.len()].copy_from_slice(case.name);
    assert!(case.name.len() < 192 && case.tail.len() <= 126);
    data[256] = case.tail.len() as u8;
    data[257..257 + case.tail.len()].copy_from_slice(case.tail);
    data[257 + case.tail.len()] = 0x0d;
    put(&mut data, 386, 256);
    put(&mut data, 390, 400);
    put(&mut data, 400, 2);
    put(&mut data, 402, case.show);
    data[720..730].copy_from_slice(b"ALIVE.OUT\0");
    let mut code = Code::default();
    code.immediate(0xba, 0);
    code.interrupt(0x3b00);
    code.fail_if(0x82);
    // Give the inherited environment a value different from the explicit one.
    code.emit(&[0x1e]);
    code.call(131);
    code.emit(&[0x8e, 0xda]);
    for (index, pair) in super::ENVIRONMENT.chunks_exact(2).enumerate() {
        code.emit(&[0xc7, 0x06]);
        code.word((index * 2) as u16);
        code.word(u16::from_le_bytes(pair.try_into().unwrap()));
    }
    code.emit(&[0x1f, 0x8c, 0xd8]); // AX = caller DS.
    code.immediate(0xa3, 388);
    code.immediate(0xa3, 392);
    if let Some(environment) = case.environment {
        assert!(environment.len() <= 64);
        code.immediate(0x68, 0); // GMEM_FIXED, DWORD allocation size.
        code.emit(&[0x66, 0x68, 64, 0, 0, 0]);
        code.call(15);
        code.emit(&[0x85, 0xc0]);
        code.fail_if(0x84);
        code.emit(&[0x89, 0xc5, 0x50]); // Retain HGLOBAL in BP; GlobalLock.
        code.call(18);
        code.emit(&[0x85, 0xd2]);
        code.fail_if(0x84);
        code.emit(&[0x1e, 0x8e, 0xda]);
        for (index, byte) in environment.iter().enumerate() {
            code.emit(&[0xc6, 0x06]);
            code.word(index as u16);
            code.emit(&[*byte]);
        }
        code.emit(&[0x1f, 0x89, 0x16]);
        code.word(384);
    }
    code.emit(&[0x1e]);
    code.immediate(0x68, 64);
    code.emit(&[0x1e]);
    code.immediate(0x68, 384);
    code.call(45);
    code.immediate(0xa3, 416);
    if case.environment.is_some() {
        code.emit(&[0x55]);
        code.call(19);
        code.emit(&[0x55]);
        code.call(17); // GlobalFree after LoadModule copied it.
        code.compare(0);
    }
    code.immediate(0xa1, 416);
    if let Some(expected) = case.expected_error {
        code.compare(expected);
    } else {
        code.immediate(0x3d, 32);
        code.fail_if(0x82);
        code.push_at(416);
        code.emit(&[0x1e]);
        code.immediate(0x68, 432);
        code.immediate(0x68, 256);
        code.call(49);
        code.emit(&[0x85, 0xc0]);
        code.fail_if(0x84);
        code.emit(&[0x89, 0xc6]);
        code.create(32);
        code.immediate(0xba, 432);
        code.emit(&[0x89, 0xf1]);
        code.interrupt(0x4000);
        code.fail_if(0x82);
        code.close();
        code.release_module(416, 1);
        code.immediate(0xa3, 418);
        code.release_module(416, 0);
        // The child waits for this file, so its later output proves that
        // FreeModule closed the caller's lease without terminating the child.
        code.create(48);
        code.close();
        code.immediate(0xbd, 4096);
        let poll = code.bytes.len();
        code.emit(&[0x4d]);
        code.fail_if(0x84);
        code.call(29);
        code.immediate(0xba, 720);
        code.interrupt(0x3d00);
        code.branch(0x82, poll);
        code.emit(&[0x89, 0xc3]);
        code.immediate(0xba, 704);
        code.immediate(0xb9, 1);
        code.interrupt(0x3f00);
        code.fail_if(0x82);
        code.emit(&[0x89, 0xc6]);
        code.close();
        code.emit(&[0x89, 0xf0]);
        code.immediate(0x3d, 1);
        code.branch(0x85, poll);
    }
    code.record(16, 416, 4);
    ne("PARENT", &code.finish(), &data, &["KERNEL"], false)
}

pub fn child_after_release() -> Vec<u8> {
    super::child_program(true)
}

pub(super) fn wait_for_release(code: &mut Code, data: &mut [u8]) {
    data[128..139].copy_from_slice(b"RELEASE.OK\0");
    data[144..154].copy_from_slice(b"ALIVE.OUT\0");
    data[304] = b'A';
    code.immediate(0xbd, 4096);
    let poll = code.bytes.len();
    code.emit(&[0x4d]);
    code.fail_if(0x84);
    code.call(29);
    code.immediate(0xba, 128);
    code.interrupt(0x3d00);
    code.branch(0x82, poll);
    code.emit(&[0x89, 0xc3]);
    code.close();
    code.record(144, 304, 1);
}

pub fn library() -> Vec<u8> {
    let mut data = vec![0; 512];
    data[32..41].copy_from_slice(b"INIT.OUT\0");
    data[48..56].copy_from_slice(b"WEP.OUT\0");
    data[97] = b'W';
    let mut code = Code::default();
    code.emit(&[0xff, 0x06]);
    code.word(104); // Count real LibEntry invocations.
    code.record(32, 104, 2);
    code.library_return(0);
    let wep = code.bytes.len() as u16;
    code.record(48, 97, 1);
    code.library_return(2);
    ne_with_exports("LIB", &code, &data, &[], true, &[("WEP", wep)])
}

pub fn module_library_parent() -> Vec<u8> {
    let mut data = vec![0; 1024];
    data[..8].copy_from_slice(b"..\\WORK\0");
    data[16..27].copy_from_slice(b"RESULT.OUT\0");
    data[32..40].copy_from_slice(b"WEP.OUT\0");
    data[64..76].copy_from_slice(b"BIN\\LIB.DLL\0");
    data[128..135].copy_from_slice(b"KERNEL\0");
    let mut code = Code::default();
    code.immediate(0xba, 0);
    code.interrupt(0x3b00);
    code.fail_if(0x82);
    // DLL initialization ignores EXECBLOCK, even for the first disk load.
    code.module_by_name(64, 0xdead_0000);
    code.immediate(0x3d, 32);
    code.fail_if(0x82);
    code.immediate(0xa3, 416);
    code.module_by_name(64, 0);
    code.emit(&[0x3b, 0x06]);
    code.word(416);
    code.fail_if(0x85);
    code.module_usage(416, 2);
    code.release_module(416, 1);
    code.module_usage(416, 1);
    code.immediate(0xba, 32);
    code.interrupt(0x3d00);
    code.fail_if(0x83); // WEP must not have run after the first reference.
    code.release_module(416, 1);
    code.release_module(416, 0);
    code.module_by_name(128, 0);
    code.immediate(0x3d, 32);
    code.fail_if(0x82);
    code.immediate(0xa3, 420);
    code.module_by_name(128, u32::MAX);
    code.emit(&[0x3b, 0x06]);
    code.word(420);
    code.fail_if(0x85);
    code.module_usage(420, 3); // One static KERNEL edge and two explicit refs.
    code.push_at(420);
    code.call(96);
    code.module_usage(420, 2);
    code.release_module(420, 1);
    code.module_usage(420, 1);
    code.release_module(420, 0);
    code.record(16, 416, 2);
    ne("PARENT", &code.finish(), &data, &["KERNEL"], false)
}
