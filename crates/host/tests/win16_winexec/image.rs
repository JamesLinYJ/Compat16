//! Minimal fixed-layout NE fixtures. The opcodes are guest data, not host asm.

pub const ENVIRONMENT: &[u8; 20] = b"C16=guest\0PATH=BIN\0\0";

#[path = "image/child_dialog.rs"]
mod child_dialog;
pub use child_dialog::child_dialog_program;

#[path = "image/registry.rs"]
mod registry;
pub use registry::{registry_program, registry_query_program};

#[path = "image/oem_bitmap.rs"]
mod oem_bitmap;
pub use oem_bitmap::oem_bitmap_program;

#[path = "image/current_directory.rs"]
mod current_directory;
pub use current_directory::{current_directory_com, current_directory_program};

#[path = "image/global_notify.rs"]
mod global_notify;
pub use global_notify::global_notify_program;

#[path = "image/dialog_icon.rs"]
mod dialog_icon;
pub use dialog_icon::{named_class_dialog_icon_program, named_dialog_icon_program};

#[path = "image/printer.rs"]
mod printer;
pub use printer::{default_printer_round_trip_program, ext_device_mode_round_trip_program};

#[path = "image/load_module.rs"]
mod load_module;
pub use load_module::{
    ModuleLaunch, child_after_release, library, module_library_parent, module_parent,
};

#[derive(Default)]
struct Code {
    bytes: Vec<u8>,
    imports: Vec<(u16, u16, u16)>,
    failures: Vec<usize>,
}

impl Code {
    fn word(&mut self, value: u16) {
        self.bytes.extend(value.to_le_bytes());
    }
    fn emit(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }
    fn immediate(&mut self, opcode: u8, value: u16) {
        self.bytes.push(opcode);
        self.word(value);
    }
    fn call(&mut self, ordinal: u16) {
        self.bytes.push(0x9a); // CALL FAR ptr16:16, imported KERNEL ordinal.
        self.imports.push((self.bytes.len() as u16, 1, ordinal));
        self.bytes.extend([0, 0, 0, 0]);
    }
    fn fail_if(&mut self, condition: u8) {
        self.bytes.extend([0x0f, condition]);
        self.failures.push(self.bytes.len());
        self.word(0);
    }
    fn interrupt(&mut self, ax: u16) {
        self.immediate(0xb8, ax);
        self.emit(&[0xcd, 0x21]);
    }
    fn finish(mut self) -> Self {
        self.interrupt(0x4c00);
        let failure = self.bytes.len();
        self.interrupt(0x4c01);
        for site in &self.failures {
            let relative = i16::try_from(failure as isize - (*site + 2) as isize).unwrap();
            self.bytes[*site..*site + 2].copy_from_slice(&relative.to_le_bytes());
        }
        self
    }
}

pub fn parent(command: &[u8], expected: Option<u16>) -> Vec<u8> {
    parent_program(command, expected, true, 0)
}

pub fn parent_with_show(command: &[u8], show: u16) -> Vec<u8> {
    parent_program(command, None, true, show)
}

pub fn native_parent(command: &[u8]) -> Vec<u8> {
    parent_program(command, None, false, 0)
}

fn parent_program(command: &[u8], expected: Option<u16>, check_child: bool, show: u16) -> Vec<u8> {
    let mut data = vec![0_u8; 512];
    data[..8].copy_from_slice(b"..\\WORK\0");
    data[16..27].copy_from_slice(b"RESULT.OUT\0");
    data[32..42].copy_from_slice(b"CHILD.OUT\0");
    data[64..64 + command.len()].copy_from_slice(command);
    let mut code = Code::default();
    code.immediate(0xba, 0); // DX = new task cwd.
    code.interrupt(0x3b00);
    code.fail_if(0x82); // JC
    code.emit(&[0x1e]); // Preserve DS while editing the live guest env.
    code.call(131);
    code.emit(&[0x8e, 0xda]); // DS = returned environment selector in DX.
    for (index, pair) in ENVIRONMENT.chunks_exact(2).enumerate() {
        code.emit(&[0xc7, 0x06]);
        code.word((index * 2) as u16);
        code.word(u16::from_le_bytes(pair.try_into().unwrap()));
    }
    code.emit(&[0x1f, 0x1e]); // Restore DS; push command far pointer segment.
    code.immediate(0x68, 64); // Offset.
    code.immediate(0x68, show); // No fixture constructs a GUI window.
    code.call(166);
    code.immediate(0xa3, 256); // Preserve the real API result.
    if let Some(expected) = expected {
        code.immediate(0x3d, expected);
        code.fail_if(0x85); // JNE
    } else {
        code.immediate(0x3d, 32);
        code.fail_if(0x82); // JB
        if check_child {
            code.immediate(0xba, 32);
            code.interrupt(0x3d00);
            code.fail_if(0x82);
            code.emit(&[0x89, 0xc3]);
            code.interrupt(0x3e00);
        }
    }
    code.immediate(0xba, 16);
    code.immediate(0xb9, 0);
    code.interrupt(0x3c00);
    code.fail_if(0x82);
    code.emit(&[0x89, 0xc3]); // BX = owned DOS file.
    code.immediate(0xba, 256);
    code.immediate(0xb9, 2);
    code.interrupt(0x4000);
    code.fail_if(0x82);
    code.interrupt(0x3e00);
    ne("PARENT", &code.finish(), &data, &["KERNEL"], false)
}

pub fn child() -> Vec<u8> {
    child_program(false)
}

fn child_program(wait_for_release: bool) -> Vec<u8> {
    let mut data = vec![0_u8; 512];
    data[32..42].copy_from_slice(b"CHILD.OUT\0");
    let mut code = Code::default();
    code.call(91); // Actual CRT startup contract: InitTask returns nCmdShow in DX.
    code.emit(&[0x89, 0x16]);
    code.word(116);
    code.call(37); // GetCurrentPDB -> AX selector.
    code.emit(&[0x89, 0xc3, 0x1e, 0x06, 0x8c, 0xd8, 0x8e, 0xc0, 0x8e, 0xdb]);
    code.immediate(0xbe, 0x80);
    code.immediate(0xbf, 64);
    code.immediate(0xb9, 32);
    code.emit(&[0xfc, 0xf3, 0xa4, 0x07, 0x1f]); // Copy PSP length/tail; restore ES/DS.
    code.call(131); // GetDOSEnvironment -> DX:AX.
    code.emit(&[0x1e, 0x06, 0x8c, 0xd8, 0x8e, 0xc0, 0x8e, 0xda]);
    code.immediate(0xbe, 0);
    code.immediate(0xbf, 96);
    code.immediate(0xb9, 20);
    code.emit(&[0xfc, 0xf3, 0xa4, 0x07, 0x1f]);
    code.immediate(0xba, 32);
    code.immediate(0xb9, 0);
    code.interrupt(0x3c00);
    code.fail_if(0x82);
    code.emit(&[0x89, 0xc3]);
    code.immediate(0xba, 64);
    code.immediate(0xb9, 54);
    code.interrupt(0x4000);
    code.fail_if(0x82);
    code.interrupt(0x3e00);
    code.call(29); // Publish readiness only after the output exists.
    if wait_for_release {
        load_module::wait_for_release(&mut code, &mut data);
    }
    ne("CHILD", &code.finish(), &data, &["KERNEL"], false)
}

pub fn failing_app() -> Vec<u8> {
    ne(
        "FAILAPP",
        &Code::default().finish(),
        &[0; 512],
        &["FAIL"],
        false,
    )
}

pub fn failing_dll() -> Vec<u8> {
    let mut code = Code::default();
    // The NE header points to LibEntry: its inputs are registers. Only the
    // C LibMain called by a CRT wrapper receives Pascal stack arguments.
    code.emit(&[0x31, 0xc0, 0xcb]); // LibEntry returns FALSE with a plain RETF.
    ne("FAIL", &code, &[0; 512], &[], true)
}

fn put(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn ne(name: &str, code: &Code, data: &[u8], modules: &[&str], library: bool) -> Vec<u8> {
    ne_with_exports(name, code, data, modules, library, &[])
}

fn ne_with_exports(
    name: &str,
    code: &Code,
    data: &[u8],
    modules: &[&str],
    library: bool,
    exports: &[(&str, u16)],
) -> Vec<u8> {
    // Microsoft NE layout: two segment records, counted resident/module
    // strings, and eight-byte additive imported-ordinal relocation records.
    let code_end = 0x200 + code.bytes.len()
        + if code.imports.is_empty() { 0 } else { 2 + code.imports.len() * 8 };
    let data_offset = code_end.next_multiple_of(16).max(0x600);
    let mut bytes = vec![0_u8; data_offset + data.len()];
    bytes[..2].copy_from_slice(b"MZ");
    put(&mut bytes, 8, 4);
    bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
    let h = 0x40;
    bytes[h..h + 2].copy_from_slice(b"NE");
    put(&mut bytes, h + 0x0c, if library { 0x8001 } else { 2 });
    put(&mut bytes, h + 0x0e, 2);
    put(&mut bytes, h + 0x10, 0x100);
    put(&mut bytes, h + 0x12, 0x400);
    put(&mut bytes, h + 0x16, 1);
    put(&mut bytes, h + 0x18, 0x0f00);
    put(&mut bytes, h + 0x1a, if library { 0 } else { 2 });
    put(&mut bytes, h + 0x1c, 2);
    put(&mut bytes, h + 0x1e, modules.len() as u16);
    put(&mut bytes, h + 0x22, 0x40);
    put(&mut bytes, h + 0x26, 0x50);
    put(&mut bytes, h + 0x32, 4);
    bytes[h + 0x36] = 2;
    put(&mut bytes, h + 0x3e, 0x030a);
    let mut cursor = h + 0x50;
    bytes[cursor] = name.len() as u8;
    cursor += 1;
    bytes[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
    cursor += name.len() + 2;
    for (index, (export, _)) in exports.iter().enumerate() {
        bytes[cursor] = export.len() as u8;
        cursor += 1;
        bytes[cursor..cursor + export.len()].copy_from_slice(export.as_bytes());
        cursor += export.len();
        put(&mut bytes, cursor, index as u16 + 1);
        cursor += 2;
    }
    cursor += 1; // Zero name terminates the resident name table.
    put(&mut bytes, h + 0x28, (cursor - h) as u16);
    let references = cursor;
    cursor += modules.len() * 2;
    put(&mut bytes, h + 0x2a, (cursor - h) as u16);
    let names = cursor;
    for (index, name) in modules.iter().enumerate() {
        put(&mut bytes, references + index * 2, (cursor - names) as u16);
        bytes[cursor] = name.len() as u8;
        cursor += 1;
        bytes[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
        cursor += name.len();
    }
    put(&mut bytes, h + 4, (cursor - h) as u16);
    put(
        &mut bytes,
        h + 6,
        if exports.is_empty() {
            1
        } else {
            (3 + exports.len() * 3) as u16
        },
    );
    if !exports.is_empty() {
        bytes[cursor] = exports.len() as u8;
        bytes[cursor + 1] = 1; // Fixed entries in the first code segment.
        cursor += 2;
        for (_, offset) in exports {
            bytes[cursor] = 1;
            put(&mut bytes, cursor + 1, *offset);
            cursor += 3;
        }
    }
    cursor += 1;
    assert!(cursor < 0x200);
    put(&mut bytes, 0x80, 0x20);
    put(&mut bytes, 0x82, code.bytes.len() as u16);
    put(
        &mut bytes,
        0x84,
        if code.imports.is_empty() { 0 } else { 0x100 },
    );
    put(&mut bytes, 0x86, 0x1000);
    put(&mut bytes, 0x88, u16::try_from(data_offset / 16).unwrap());
    put(&mut bytes, 0x8a, data.len() as u16);
    put(&mut bytes, 0x8c, 1);
    put(&mut bytes, 0x8e, 0x1000);
    bytes[0x200..0x200 + code.bytes.len()].copy_from_slice(&code.bytes);
    let mut fixup = 0x200 + code.bytes.len();
    if !code.imports.is_empty() {
        put(&mut bytes, fixup, code.imports.len() as u16);
        fixup += 2;
        for (source, module, ordinal) in &code.imports {
            bytes[fixup] = 3;
            bytes[fixup + 1] = 5;
            put(&mut bytes, fixup + 2, *source);
            put(&mut bytes, fixup + 4, *module);
            put(&mut bytes, fixup + 6, *ordinal);
            fixup += 8;
        }
    }
    assert!(fixup <= data_offset);
    bytes[data_offset..].copy_from_slice(data);
    bytes
}
