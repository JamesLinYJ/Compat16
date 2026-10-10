//! Service-gate regression coverage for guest-only USER rectangle helpers.

use super::super::ImportBinding;
use crate::{Runtime, RuntimeError, RuntimeHost};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, lookup_export};

// These APIs only operate on checked guest memory. Any required host service
// being reached is a test failure, rather than an invented successful reply.
struct NoHost;

impl DosHost for NoHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, _path: &[u8], _access: DosFileAccess) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open_with_sharing(&mut self, _path: &[u8], _access: DosFileAccess, _sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_seek(&mut self, _file: DosHostFile, _offset: i32, _origin: DosSeekOrigin) -> Result<u32, DosHostError> { panic!("unexpected host call") }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_get_current(&mut self, _drive: u8, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> { panic!("unexpected host call") }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> { panic!("unexpected host call") }
    fn directory_search_next(&mut self, _search: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> { panic!("unexpected host call") }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn guest_code_page(&self) -> text_codec::CodePage { panic!("unexpected host call") }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { panic!("unexpected host call") }
}

impl RuntimeHost for NoHost {
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}

impl crate::RuntimeDdeHost for NoHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}

impl crate::RuntimeMciHost for NoHost {}
impl crate::RuntimeMidiHost for NoHost {}
impl crate::RuntimeNetbiosHost for NoHost {}

const FIRST: u16 = 0x10;
const SECOND: u16 = 0x20;
const OUTPUT: u16 = 0x30;
const AX_SENTINEL: u16 = 0xa55a;
const DX_SENTINEL: u16 = 0x5aa5;

fn write_rect(runtime: &mut Runtime, offset: u16, edges: [i16; 4]) {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), offset).unwrap();
    let bytes: Vec<u8> = edges.into_iter().flat_map(i16::to_le_bytes).collect();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
}

fn read_rect(runtime: &Runtime, offset: u16) -> [i16; 4] {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), offset).unwrap();
    let mut bytes = [0; 8];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    std::array::from_fn(|i| i16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]))
}

fn prepare_call(runtime: &mut Runtime, ordinal: u16, offsets: &[u16]) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    // Pascal arguments appear right-to-left when read upwards from the FAR
    // return address. Every argument here is a four-byte guest FAR pointer.
    for &offset in offsets.iter().rev() {
        let far = if offset == u16::MAX { 0 } else {
            (u32::from(runtime.cpu.regs.ds) << 16) | u32::from(offset)
        };
        bytes.extend_from_slice(&far.to_le_bytes());
    }
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(AX_SENTINEL);
    runtime.cpu.regs.set_dx(DX_SENTINEL);
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(runtime: &mut Runtime) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0,
    )
}

#[test]
fn rectangle_exports_reach_existing_handlers_through_service_gate() {
    let first = [1, 2, 8, 9];
    let second = [0, 2, 4, 9];
    // Void APIs must preserve AX; BOOL APIs must publish their real result.
    for (ordinal, offsets, expected, ax) in [
        (73, vec![OUTPUT], [0; 4], AX_SENTINEL),
        (74, vec![OUTPUT, FIRST], first, AX_SENTINEL),
        (80, vec![OUTPUT, FIRST, SECOND], [0, 2, 8, 9], 1),
        (244, vec![FIRST, FIRST], [99; 4], 1),
        (244, vec![FIRST, SECOND], [99; 4], 0),
        (373, vec![OUTPUT, FIRST, SECOND], [4, 2, 8, 9], 1),
        (373, vec![OUTPUT, FIRST, FIRST], [0; 4], 0),
        // Both source values must be read before overwriting an aliased output.
        (74, vec![FIRST, FIRST], [99; 4], AX_SENTINEL),
        (80, vec![FIRST, FIRST, SECOND], [99; 4], 1),
        (373, vec![FIRST, FIRST, SECOND], [99; 4], 1),
    ] {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], b"C:\\RECT.NE").unwrap();
        write_rect(&mut runtime, FIRST, first);
        write_rect(&mut runtime, SECOND, second);
        write_rect(&mut runtime, OUTPUT, [99; 4]);
        let return_to = prepare_call(&mut runtime, ordinal, &offsets);
        assert_eq!(dispatch(&mut runtime).unwrap(), None, "USER.{ordinal}");
        assert_eq!(read_rect(&runtime, OUTPUT), expected, "USER.{ordinal}");
        if offsets[0] == FIRST && ordinal != 244 {
            let expected_first = match ordinal {
                80 => [0, 2, 8, 9],
                373 => [4, 2, 8, 9],
                _ => first,
            };
            assert_eq!(read_rect(&runtime, FIRST), expected_first, "USER.{ordinal}");
        }
        assert_eq!(runtime.cpu.regs.ax(), ax, "USER.{ordinal}");
        assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL, "USER.{ordinal}");
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
    }
}

#[test]
fn rectangle_exports_reject_invalid_far_pointers_before_writing() {
    for (ordinal, offsets) in [
        (73, vec![u16::MAX]),
        (74, vec![OUTPUT, u16::MAX]),
        (80, vec![OUTPUT, FIRST, u16::MAX]),
        (244, vec![FIRST, u16::MAX]),
        (373, vec![OUTPUT, FIRST, u16::MAX]),
    ] {
        let mut runtime = Runtime::load(&tiny_ne_executable(), &[], b"C:\\RECT.NE").unwrap();
        write_rect(&mut runtime, FIRST, [1, 2, 8, 9]);
        write_rect(&mut runtime, OUTPUT, [99; 4]);
        prepare_call(&mut runtime, ordinal, &offsets);
        let error = dispatch(&mut runtime).unwrap_err();
        assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault, "USER.{ordinal}");
        assert_eq!(read_rect(&runtime, OUTPUT), [99; 4], "USER.{ordinal}");
        assert_eq!(runtime.cpu.regs.ax(), AX_SENTINEL, "USER.{ordinal}");
        assert_eq!(runtime.cpu.regs.dx(), DX_SENTINEL, "USER.{ordinal}");
    }
}

fn tiny_ne_executable() -> Vec<u8> {
    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    let mut bytes = vec![0; 0x92];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u16(&mut bytes, 0x08, 4);
    bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());

    let ne = 0x40;
    bytes[ne..ne + 2].copy_from_slice(b"NE");
    put_u16(&mut bytes, ne + 0x04, 0x51); // entry table
    put_u16(&mut bytes, ne + 0x06, 1);
    put_u16(&mut bytes, ne + 0x0e, 2); // automatic data segment
    put_u16(&mut bytes, ne + 0x10, 0x100); // heap reserve
    put_u16(&mut bytes, ne + 0x12, 0x100); // stack reserve
    put_u16(&mut bytes, ne + 0x14, 0); // initial IP
    put_u16(&mut bytes, ne + 0x16, 1); // initial CS
    put_u16(&mut bytes, ne + 0x18, 0x80); // initial SP
    put_u16(&mut bytes, ne + 0x1a, 2); // initial SS
    put_u16(&mut bytes, ne + 0x1c, 2); // segment count
    put_u16(&mut bytes, ne + 0x22, 0x40); // segment table
    put_u16(&mut bytes, ne + 0x26, 0x50); // resident names
    put_u16(&mut bytes, ne + 0x28, 0x51); // module references
    put_u16(&mut bytes, ne + 0x2a, 0x51); // imported names

    // Both segments are zero-filled: executable code followed by writable
    // automatic data. The resident-name and entry tables each have terminators.
    put_u16(&mut bytes, 0x80 + 0x04, 0x0000);
    put_u16(&mut bytes, 0x80 + 0x06, 0x0100);
    put_u16(&mut bytes, 0x88 + 0x04, 0x0001);
    put_u16(&mut bytes, 0x88 + 0x06, 0x0100);
    bytes[0x90] = 0;
    bytes[0x91] = 0;
    bytes
}
