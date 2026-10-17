//! GDI.310 path forms, register halves, and host handoff.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use super::*;
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{
    AccessRights, ExportLookupTarget, SegmentedPointer, Win16ExportStackCleanup, Win16ReturnKind,
    lookup_export,
};

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
        self.calls.push(operation);
        if self.fail {
            return Err(RuntimeError::new(Kind::HostFailure, "test native failure"));
        }
        Ok(self.result.take().expect("test supplies a native result"))
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

fn fixture() -> (Runtime, u32) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\FONT.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let selector = state
        .selectors
        .alloc_block(
            PhysAddr(0x70000),
            0x1000,
            AccessRights::read_write(),
            &runtime.memory,
        )
        .unwrap();
    (runtime, SegmentedPointer::new(selector, 0).far_value())
}

fn place(runtime: &mut Runtime, base: u32, offset: u16, bytes: Option<&[u8]>) -> u32 {
    let Some(bytes) = bytes else {
        return 0;
    };
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state
        .selectors
        .pointer_from_far(base | u32::from(offset))
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, bytes)
        .unwrap();
    base | u32::from(offset)
}

fn prepare(
    runtime: &mut Runtime,
    hidden: u16,
    resource: u32,
    font: u32,
    current: u32,
) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"GDI", ExportLookupTarget::Ordinal(310)).unwrap();
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    let Win16ExportStackCleanup::Fixed(cleanup) = descriptor.stack_cleanup else {
        panic!("fixed Pascal frame required");
    };
    assert_eq!(
        (cleanup.callee_pop_bytes, cleanup.caller_pop_bytes),
        (14, 0)
    );
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&current.to_le_bytes());
    bytes.extend_from_slice(&font.to_le_bytes());
    bytes.extend_from_slice(&resource.to_le_bytes());
    bytes.extend_from_slice(&hidden.to_le_bytes());
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

fn assert_return(runtime: &Runtime, return_to: (u16, u16, u16), result: u16) {
    assert_eq!(runtime.cpu.regs.eax, 0xa1b2_0000 | u32::from(result));
    assert_eq!(runtime.cpu.regs.edx, 0xc3d4_5aa5);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to
    );
}

fn invoke(
    hidden: u16,
    resource: Option<&[u8]>,
    font: Option<&[u8]>,
    current: Option<&[u8]>,
    host: &mut FontHost,
) -> Result<u16, Kind> {
    let (mut runtime, base) = fixture();
    let resource = place(&mut runtime, base, 0, resource);
    let font = place(&mut runtime, base, 0x100, font);
    let current = place(&mut runtime, base, 0x200, current);
    let return_to = prepare(&mut runtime, hidden, resource, font, current);
    match dispatch(&mut runtime, host) {
        Ok(_) => {
            let result = runtime.cpu.regs.eax as u16;
            assert_return(&runtime, return_to, result);
            Ok(result)
        }
        Err(error) => Err(error.kind()),
    }
}

#[test]
fn scalable_font_full_path_forwards_hidden_flag_and_preserves_register_halves() {
    let mut host = FontHost {
        result: Some(ResultValue::Bool(true)),
        ..Default::default()
    };
    let result = invoke(
        1,
        Some(b"A\x82\xa0.FOT\0"),
        Some(b"C:\\\x82\xa0.TTF\0"),
        None,
        &mut host,
    )
    .unwrap();
    assert_eq!(result, 1);
    assert_eq!(
        host.calls,
        [Operation::CreateScalableFontResource {
            hidden: 1,
            resource_file: b"A\x82\xa0.FOT".to_vec(),
            font_file: b"C:\\\x82\xa0.TTF".to_vec(),
            current_path: None,
        }]
    );
}

#[test]
fn scalable_font_bare_name_keeps_filename_and_current_path_separate() {
    let mut host = FontHost {
        result: Some(ResultValue::Bool(true)),
        ..Default::default()
    };
    let result = invoke(
        0,
        Some(b"BOOK.FOT\0"),
        Some(b"\x82\xa0.TTF\0"),
        Some(b"C:\\FONTS\\\0"),
        &mut host,
    )
    .unwrap();
    assert_eq!(result, 1);
    assert_eq!(
        host.calls,
        [Operation::CreateScalableFontResource {
            hidden: 0,
            resource_file: b"BOOK.FOT".to_vec(),
            font_file: b"\x82\xa0.TTF".to_vec(),
            current_path: Some(b"C:\\FONTS\\".to_vec()),
        }]
    );
}

#[test]
fn scalable_font_omitted_and_conflicting_paths_do_not_call_the_host() {
    for (resource, font, current) in [
        (
            Some(b"BOOK.FOT\0".as_slice()),
            Some(b"TIMES.TTF\0".as_slice()),
            None,
        ),
        (
            Some(b"BOOK.FOT\0".as_slice()),
            Some(b"TIMES.TTF\0".as_slice()),
            Some(b"\0".as_slice()),
        ),
        (
            Some(b"BOOK.FOT\0".as_slice()),
            Some(b"C:\\TIMES.TTF\0".as_slice()),
            Some(b"C:\\FONTS\0".as_slice()),
        ),
        (
            Some(b"BOOK.FOT\0".as_slice()),
            Some(b"C:TIMES.TTF\0".as_slice()),
            Some(b"C:\\FONTS\0".as_slice()),
        ),
        (
            Some(b"BOOK.FOT\0".as_slice()),
            Some(b"FONTS/TIMES.TTF\0".as_slice()),
            Some(b"C:\\FONTS\0".as_slice()),
        ),
        (
            Some(b"BOOK.FOT\0".as_slice()),
            None,
            Some(b"C:\\FONTS\0".as_slice()),
        ),
        (
            Some(b"BOOK.FOT\0".as_slice()),
            Some(b"\0".as_slice()),
            Some(b"C:\\FONTS\0".as_slice()),
        ),
        (
            Some(b"\0".as_slice()),
            Some(b"TIMES.TTF\0".as_slice()),
            Some(b"C:\\FONTS\0".as_slice()),
        ),
        (None, Some(b"C:\\TIMES.TTF\0".as_slice()), None),
    ] {
        let mut host = FontHost {
            result: Some(ResultValue::Bool(true)),
            ..Default::default()
        };
        assert_eq!(invoke(1, resource, font, current, &mut host).unwrap(), 0);
        assert!(host.calls.is_empty(), "{resource:?} {font:?} {current:?}");
    }
}

#[test]
fn scalable_font_empty_current_path_is_omitted_for_a_directory_path() {
    let mut host = FontHost {
        result: Some(ResultValue::Bool(true)),
        ..Default::default()
    };
    assert_eq!(
        invoke(
            0x8001,
            Some(b"BOOK.FOT\0"),
            Some(b"C:TIMES.TTF\0"),
            Some(b"\0"),
            &mut host,
        )
        .unwrap(),
        1
    );
    assert_eq!(
        host.calls,
        [Operation::CreateScalableFontResource {
            hidden: 0x8001,
            resource_file: b"BOOK.FOT".to_vec(),
            font_file: b"C:TIMES.TTF".to_vec(),
            current_path: None,
        }]
    );
}

#[test]
fn scalable_font_native_false_and_wrong_results_stay_distinct() {
    let mut host = FontHost {
        result: Some(ResultValue::Bool(false)),
        ..Default::default()
    };
    assert_eq!(
        invoke(
            1,
            Some(b"BOOK.FOT\0"),
            Some(b"C:\\TIMES.TTF\0"),
            None,
            &mut host,
        )
        .unwrap(),
        0
    );
    assert_eq!(host.calls.len(), 1);

    let mut host = FontHost {
        result: Some(ResultValue::Dword(1)),
        ..Default::default()
    };
    assert_eq!(
        invoke(
            1,
            Some(b"BOOK.FOT\0"),
            Some(b"C:\\TIMES.TTF\0"),
            None,
            &mut host,
        ),
        Err(Kind::InternalInvariant)
    );

    let mut host = FontHost {
        fail: true,
        ..Default::default()
    };
    assert_eq!(
        invoke(
            1,
            Some(b"BOOK.FOT\0"),
            Some(b"C:\\TIMES.TTF\0"),
            None,
            &mut host,
        ),
        Err(Kind::HostFailure)
    );
}
