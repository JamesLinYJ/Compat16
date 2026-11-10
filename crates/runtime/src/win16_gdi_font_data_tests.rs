//! GDI.311 returns zero on failure and copies only a range the table can hold.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost,
    Win16GdiServicesOperation as Operation, Win16GdiServicesResult as ResultValue, Win16HostDc,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::gdi_abi::{Win16FontDataPlan, plan_win16_font_data};
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup, Win16ReturnKind,
    lookup_export,
};

const NATIVE_DC: Win16HostDc = Win16HostDc(0x1234_5678_9abc);
const NAME_TABLE: u32 = 0x656d_616e;
const NAME_BYTES: &[u8] = b"ABCDEFGHIJKLMNOP";

#[derive(Default)]
struct FontHost {
    calls: Vec<Operation>,
    result: Option<ResultValue>,
    fail: bool,
}

impl DosHost for FontHost {
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_open_with_sharing(
        &mut self,
        _path: &[u8],
        _access: DosFileAccess,
        _sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_close(&mut self, _file: DosHostFile) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_write(&mut self, _file: DosHostFile, _input: &[u8]) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_seek(
        &mut self,
        _file: DosHostFile,
        _offset: i32,
        _origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_len(&mut self, _file: DosHostFile, _length: u32) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_delete(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_create(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_remove(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_set_current(&mut self, _path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_get_current(
        &mut self,
        _drive: u8,
        _output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_rename(&mut self, _old_path: &[u8], _new_path: &[u8]) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn file_get_attributes(&mut self, _path: &[u8]) -> Result<u8, DosHostError> {
        panic!("unexpected host call")
    }
    fn file_set_attributes(&mut self, _path: &[u8], _attributes: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_open(&mut self, _directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_next(
        &mut self,
        _search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        panic!("unexpected host call")
    }
    fn directory_search_close(&mut self, _search: DosHostSearch) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn guest_code_page(&self) -> text_codec::CodePage {
        panic!("unexpected host call")
    }
    fn current_drive(&self) -> u8 {
        panic!("unexpected host call")
    }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> {
        panic!("unexpected host call")
    }
    fn logical_drive_count(&self) -> u8 {
        panic!("unexpected host call")
    }
}

impl RuntimeHost for FontHost {
    fn win16_gdi_services(&mut self, operation: Operation) -> Result<ResultValue, RuntimeError> {
        let result = if self.fail {
            self.calls.push(operation);
            return Err(RuntimeError::new(Kind::HostFailure, "test native failure"));
        } else if let Some(result) = self.result.take() {
            result
        } else {
            font_reply(&operation)
        };
        self.calls.push(operation);
        Ok(result)
    }
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeDdeHost for FontHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for FontHost {}
impl crate::RuntimeMidiHost for FontHost {}
impl crate::RuntimeNetbiosHost for FontHost {}

fn font_reply(operation: &Operation) -> ResultValue {
    let &Operation::GetFontData {
        table,
        offset,
        byte_count,
        copy_buffer,
        ..
    } = operation
    else {
        panic!("unexpected host call");
    };
    if table != NAME_TABLE {
        return ResultValue::FontData {
            result: super::GDI_ERROR,
            bytes: Vec::new(),
        };
    }
    match plan_win16_font_data(NAME_BYTES.len() as u32, offset, byte_count, copy_buffer) {
        Win16FontDataPlan::Failure => ResultValue::FontData {
            result: 0,
            bytes: Vec::new(),
        },
        Win16FontDataPlan::TableSize => ResultValue::FontData {
            result: NAME_BYTES.len() as u32,
            bytes: Vec::new(),
        },
        Win16FontDataPlan::Copy { len } => {
            let start = offset as usize;
            let end = start + len as usize;
            ResultValue::FontData {
                result: len,
                bytes: NAME_BYTES[start..end].to_vec(),
            }
        }
    }
}

fn fixture() -> (Runtime, u16, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\FONTDATA.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let dc = state.guest_gdi.allocate_dc(NATIVE_DC).unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(0x70000),
            64,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    let pointer = SegmentedPointer::new(selector, 0);
    state
        .selectors
        .write(&mut runtime.memory, pointer, &[0x5a; 64])
        .unwrap();
    (runtime, dc, pointer.far_value())
}

fn read_output(runtime: &Runtime, far: u32) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_far(far).unwrap();
    let mut bytes = vec![0; 64];
    state
        .selectors
        .read(&runtime.memory, pointer, &mut bytes)
        .unwrap();
    bytes
}

fn prepare(
    runtime: &mut Runtime,
    dc: u16,
    table: u32,
    offset: u32,
    output: u32,
    byte_count: u32,
) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(311)).unwrap();
    assert_eq!(
        descriptor.id,
        lookup_export(b"GDI", ExportLookupTarget::Name(b"GetFontData"))
            .unwrap()
            .id
    );
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Dword);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("fixed Pascal frame required");
    };
    assert_eq!(
        (cleanup.callee_pop_bytes, cleanup.caller_pop_bytes),
        (18, 0)
    );
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&byte_count.to_le_bytes());
    bytes.extend_from_slice(&output.to_le_bytes());
    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&table.to_le_bytes());
    bytes.extend_from_slice(&dc.to_le_bytes());
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &bytes)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = 0xa1b2_a55a;
    runtime.cpu.regs.edx = 0xc3d4_5aa5;
    (return_cs, return_ip, stack + bytes.len() as u16)
}

fn dispatch(runtime: &mut Runtime, host: &mut FontHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

fn assert_dword(runtime: &Runtime, return_to: (u16, u16, u16), result: u32) {
    assert_eq!(runtime.cpu.regs.eax, 0xa1b2_0000 | u32::from(result as u16));
    assert_eq!(
        runtime.cpu.regs.edx,
        0xc3d4_0000 | u32::from((result >> 16) as u16)
    );
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
}

#[test]
fn get_font_data_miss_returns_zero_and_leaves_the_buffer() {
    let (mut runtime, dc, output) = fixture();
    let return_to = prepare(&mut runtime, dc, 0x2222_2222, 0, output, 4);
    let mut host = FontHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_dword(&runtime, return_to, 0);
    assert_eq!(read_output(&runtime, output), [0x5a; 64]);
    assert!(matches!(
        host.calls.as_slice(),
        [Operation::GetFontData {
            table: 0x2222_2222,
            copy_buffer: true,
            byte_count: 4,
            ..
        }]
    ));

    let (mut runtime, _dc, output) = fixture();
    let return_to = prepare(&mut runtime, 0xffff, NAME_TABLE, 0, output, 4);
    let mut host = FontHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_dword(&runtime, return_to, 0);
    assert!(host.calls.is_empty());
    assert_eq!(read_output(&runtime, output), [0x5a; 64]);

    // An offset at or beyond the table, and a copy longer than the bytes
    // that remain, fail with zero. The guest buffer stays unchanged.
    for (offset, byte_count) in [(16, 4), (20, 0), (0, 17), (12, 8)] {
        let (mut runtime, dc, output) = fixture();
        let return_to = prepare(&mut runtime, dc, NAME_TABLE, offset, output, byte_count);
        let mut host = FontHost::default();
        dispatch(&mut runtime, &mut host).unwrap();
        assert_dword(&runtime, return_to, 0);
        assert_eq!(host.calls.len(), 1);
        assert_eq!(read_output(&runtime, output), [0x5a; 64]);
    }

    let (mut runtime, dc, output) = fixture();
    prepare(&mut runtime, dc, NAME_TABLE, 0, output, 4);
    let mut host = FontHost {
        result: Some(ResultValue::FontData {
            result: super::GDI_ERROR,
            bytes: vec![1, 2, 3, 4],
        }),
        ..Default::default()
    };
    assert_eq!(
        dispatch(&mut runtime, &mut host).unwrap_err().kind(),
        Kind::InternalInvariant
    );
    assert_eq!(read_output(&runtime, output), [0x5a; 64]);
}

#[test]
fn get_font_data_short_buffer_copies_only_the_requested_prefix() {
    let (mut runtime, dc, output) = fixture();
    let return_to = prepare(&mut runtime, dc, NAME_TABLE, 2, output, 4);
    let mut host = FontHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_dword(&runtime, return_to, 4);
    let bytes = read_output(&runtime, output);
    assert_eq!(&bytes[..4], b"CDEF");
    assert_eq!(&bytes[4..], &[0x5a; 60]);
    assert_eq!(
        host.calls,
        [Operation::GetFontData {
            dc: NATIVE_DC,
            table: NAME_TABLE,
            offset: 2,
            byte_count: 4,
            copy_buffer: true,
        }]
    );
}

#[test]
fn get_font_data_successful_copy_writes_the_table_and_returns_its_length() {
    let (mut runtime, dc, output) = fixture();
    let return_to = prepare(
        &mut runtime,
        dc,
        NAME_TABLE,
        0,
        output,
        NAME_BYTES.len() as u32,
    );
    let mut host = FontHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_dword(&runtime, return_to, NAME_BYTES.len() as u32);
    let bytes = read_output(&runtime, output);
    assert_eq!(&bytes[..NAME_BYTES.len()], NAME_BYTES);
    assert_eq!(&bytes[NAME_BYTES.len()..], &[0x5a; 64 - NAME_BYTES.len()]);

    let (mut runtime, dc, output) = fixture();
    let return_to = prepare(&mut runtime, dc, NAME_TABLE, 0, 0, 0);
    let mut host = FontHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_dword(&runtime, return_to, NAME_BYTES.len() as u32);
    assert_eq!(read_output(&runtime, output), [0x5a; 64]);
    assert!(matches!(
        host.calls.as_slice(),
        [Operation::GetFontData {
            byte_count: 0,
            copy_buffer: false,
            ..
        }]
    ));

    let (mut runtime, dc, output) = fixture();
    let return_to = prepare(&mut runtime, dc, NAME_TABLE, 1, output, 0);
    let mut host = FontHost::default();
    dispatch(&mut runtime, &mut host).unwrap();
    assert_dword(&runtime, return_to, NAME_BYTES.len() as u32);
    assert_eq!(read_output(&runtime, output), [0x5a; 64]);
}
