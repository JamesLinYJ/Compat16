//! KERNEL.74 service-gate, OFSTRUCT preflight, and opaque file ownership tests.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost,
    Win16HostFile, Win16HostFileClose, Win16HostOpenFile};
use compat_services::win16_lzexpand::OFSTRUCT_BYTES;
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};
use guest_core::{PhysAddr, Selector};
use win16_abi::{AccessRights, ExportLookupTarget, SegmentedPointer, lookup_export};

const BASE: u32 = 0x80000;
const OF_REOPEN_VERIFY: u16 = 0x8400;
const EAX_SENTINEL: u32 = 0x1357_a55a;
const EDX_SENTINEL: u32 = 0x2468_5aa5;
const HOST_FILE: Win16HostFile = Win16HostFile(0x1234_5678_9abc_def0);

struct OpenFileHost {
    response: Option<Result<Win16HostOpenFile, RuntimeError>>,
    opened: Vec<(Vec<u8>, u16, Vec<u8>)>,
    closed: Vec<Win16HostFile>,
}

impl OpenFileHost {
    fn new(response: Result<Win16HostOpenFile, RuntimeError>) -> Self {
        Self { response: Some(response), opened: Vec::new(), closed: Vec::new() }
    }
}

impl DosHost for OpenFileHost {
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

impl RuntimeHost for OpenFileHost {
    fn win16_open_file(&mut self, path: &[u8], style: u16, previous: Vec<u8>)
        -> Result<Win16HostOpenFile, RuntimeError> {
        self.opened.push((path.to_vec(), style, previous));
        self.response.take().expect("only one native open expected")
    }
    fn win16_file_close(&mut self, file: Win16HostFile) -> Result<Win16HostFileClose, RuntimeError> {
        self.closed.push(file);
        Ok(Win16HostFileClose { closed: true, consumed_source: None })
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for OpenFileHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for OpenFileHost {}
impl crate::RuntimeMidiHost for OpenFileHost {}
impl crate::RuntimeNetbiosHost for OpenFileHost {}

fn fixture(size: usize, rights: AccessRights) -> (Runtime, u32) {
    // Reuse the ordinary service-gate fixture without adding an NE generator.
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\OPENFILE.NE").unwrap();
    runtime.memory.write_physical(PhysAddr(BASE - 1), &vec![0x5a; OFSTRUCT_BYTES + 2]).unwrap();
    let selector = runtime.win16.as_mut().unwrap().selectors
        .alloc_block(PhysAddr(BASE), size as u32, rights, &runtime.memory).unwrap();
    (runtime, SegmentedPointer::new(selector, 0).far_value())
}

fn prepare_gate(runtime: &mut Runtime, path: u32, ofstruct: u32, style: u16) -> (u16, u16, u16) {
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    // Pascal stack order is the reverse of the C declaration's arguments.
    frame.extend_from_slice(&style.to_le_bytes());
    frame.extend_from_slice(&ofstruct.to_le_bytes());
    frame.extend_from_slice(&path.to_le_bytes());
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &frame).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(
        lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(74)).unwrap()));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = EAX_SENTINEL;
    runtime.cpu.regs.edx = EDX_SENTINEL;
    (return_cs, return_ip, stack + 14)
}

fn dispatch(runtime: &mut Runtime, host: &mut OpenFileHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0)
}

fn output_with_guards(runtime: &Runtime) -> Vec<u8> {
    let mut bytes = vec![0; OFSTRUCT_BYTES + 2];
    runtime.memory.read_physical(PhysAddr(BASE - 1), &mut bytes).unwrap();
    bytes
}

fn frame_position(runtime: &Runtime) -> (u16, u16, u16) {
    (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp())
}

fn assert_return(runtime: &Runtime, expected: u16, return_to: (u16, u16, u16)) {
    assert_eq!(runtime.cpu.regs.eax, (EAX_SENTINEL & 0xffff_0000) | u32::from(expected));
    assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
    assert_eq!(frame_position(runtime), return_to);
}

fn assert_unchanged_frame(runtime: &Runtime, position: (u16, u16, u16)) {
    assert_eq!((runtime.cpu.regs.eax, runtime.cpu.regs.edx), (EAX_SENTINEL, EDX_SENTINEL));
    assert_eq!(frame_position(runtime), position);
}

#[test]
fn open_file_reopen_gate_returns_guest_hfile_in_ax_and_preserves_dx() {
    let (mut runtime, ofstruct) = fixture(OFSTRUCT_BYTES, AccessRights::read_write());
    let output: Vec<u8> = (0..OFSTRUCT_BYTES).map(|byte| byte as u8).collect();
    let mut host = OpenFileHost::new(Ok(Win16HostOpenFile {
        result: 0, file: Some(HOST_FILE), ofstruct: output.clone(),
    }));
    let return_to = prepare_gate(&mut runtime, 0xfff8_ffff, ofstruct, OF_REOPEN_VERIFY);
    let preserved = (runtime.cpu.regs.ds, runtime.cpu.regs.ss,
        runtime.cpu.regs.ebp, runtime.cpu.regs.esi, runtime.cpu.regs.edi);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_return(&runtime, super::FIRST_GUEST_HFILE, return_to);
    assert_eq!((runtime.cpu.regs.ds, runtime.cpu.regs.ss,
        runtime.cpu.regs.ebp, runtime.cpu.regs.esi, runtime.cpu.regs.edi), preserved);
    assert_eq!(host.opened, [(Vec::new(), OF_REOPEN_VERIFY, vec![0x5a; OFSTRUCT_BYTES])]);
    assert!(host.closed.is_empty());
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.files.len(), 1);
    assert_eq!(state.files.get(&super::FIRST_GUEST_HFILE), Some(&HOST_FILE));
    let bytes = output_with_guards(&runtime);
    assert_eq!((bytes[0], bytes[OFSTRUCT_BYTES + 1]), (0x5a, 0x5a));
    assert_eq!(&bytes[1..=OFSTRUCT_BYTES], output);
}

#[test]
fn open_file_invalid_ofstruct_prevents_native_open_and_leaves_guest_state() {
    for case in 0..6 {
        let rights = match case {
            1 => AccessRights::read_only(),
            2 => AccessRights::new(false, false, true),
            _ => AccessRights::read_write(),
        };
        let size = if case == 3 { OFSTRUCT_BYTES - 1 } else { OFSTRUCT_BYTES };
        let (mut runtime, mut ofstruct) = fixture(size, rights);
        if case == 0 { ofstruct = 0; }
        if case == 4 { ofstruct = 0xfff8_0000; }
        if case == 5 {
            let state = runtime.win16.as_mut().unwrap();
            let selector = state.selectors.pointer_from_far(ofstruct).unwrap().selector();
            state.selectors.free_block(selector).unwrap();
        }
        let mut host = OpenFileHost::new(Ok(Win16HostOpenFile {
            result: 0, file: Some(HOST_FILE), ofstruct: vec![0; OFSTRUCT_BYTES],
        }));
        prepare_gate(&mut runtime, 0xfff8_ffff, ofstruct, OF_REOPEN_VERIFY);
        let before = frame_position(&runtime);
        let bytes = output_with_guards(&runtime);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::GuestFault);
        assert_unchanged_frame(&runtime, before);
        assert_eq!(output_with_guards(&runtime), bytes);
        assert!(runtime.win16.as_ref().unwrap().files.is_empty());
        assert!(host.opened.is_empty());
        assert!(host.closed.is_empty());
        assert!(host.response.is_some());
    }
}

#[test]
fn open_file_host_error_does_not_publish_buffer_or_commit_return_frame() {
    let (mut runtime, ofstruct) = fixture(OFSTRUCT_BYTES, AccessRights::read_write());
    let mut host = OpenFileHost::new(Err(RuntimeError::new(Kind::HostFailure, "test open failure")));
    prepare_gate(&mut runtime, 0xfff8_ffff, ofstruct, OF_REOPEN_VERIFY);
    let before = frame_position(&runtime);
    let bytes = output_with_guards(&runtime);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::HostFailure);
    assert_unchanged_frame(&runtime, before);
    assert_eq!(output_with_guards(&runtime), bytes);
    assert_eq!(host.opened.len(), 1);
    assert!(host.closed.is_empty());
    assert!(runtime.win16.as_ref().unwrap().files.is_empty());
}

#[test]
fn open_file_api_failure_publishes_ofstruct_and_returns_hfile_error() {
    let (mut runtime, ofstruct) = fixture(OFSTRUCT_BYTES, AccessRights::read_write());
    let mut output = vec![0; OFSTRUCT_BYTES];
    output[0] = OFSTRUCT_BYTES as u8;
    output[2..4].copy_from_slice(&2_u16.to_le_bytes());
    let mut host = OpenFileHost::new(Ok(Win16HostOpenFile {
        result: -1, file: None, ofstruct: output.clone(),
    }));
    let return_to = prepare_gate(&mut runtime, 0xfff8_ffff, ofstruct, OF_REOPEN_VERIFY);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_return(&runtime, 0xffff, return_to);
    assert_eq!(&output_with_guards(&runtime)[1..=OFSTRUCT_BYTES], output);
    assert!(host.closed.is_empty());
    assert!(runtime.win16.as_ref().unwrap().files.is_empty());
}

#[test]
fn open_file_malformed_host_ofstruct_closes_unpublished_token() {
    for size in [OFSTRUCT_BYTES - 1, OFSTRUCT_BYTES + 1] {
        let (mut runtime, ofstruct) = fixture(OFSTRUCT_BYTES, AccessRights::read_write());
        let mut host = OpenFileHost::new(Ok(Win16HostOpenFile {
            result: 0, file: Some(HOST_FILE), ofstruct: vec![0; size],
        }));
        prepare_gate(&mut runtime, 0xfff8_ffff, ofstruct, OF_REOPEN_VERIFY);
        let before = frame_position(&runtime);
        let bytes = output_with_guards(&runtime);
        assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::InternalInvariant);
        assert_unchanged_frame(&runtime, before);
        assert_eq!(output_with_guards(&runtime), bytes);
        assert_eq!(host.closed, [HOST_FILE]);
        assert!(runtime.win16.as_ref().unwrap().files.is_empty());
    }
}

#[test]
fn open_file_failed_host_result_with_token_closes_it_and_rejects_success() {
    let (mut runtime, ofstruct) = fixture(OFSTRUCT_BYTES, AccessRights::read_write());
    let mut host = OpenFileHost::new(Ok(Win16HostOpenFile {
        result: -1, file: Some(HOST_FILE), ofstruct: vec![0; OFSTRUCT_BYTES],
    }));
    prepare_gate(&mut runtime, 0xfff8_ffff, ofstruct, OF_REOPEN_VERIFY);
    let before = frame_position(&runtime);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap_err().kind(), Kind::InternalInvariant);
    assert_unchanged_frame(&runtime, before);
    assert_eq!(host.closed, [HOST_FILE]);
    assert!(runtime.win16.as_ref().unwrap().files.is_empty());
}

#[test]
fn open_file_guest_hfile_exhaustion_closes_only_the_new_host_token() {
    let (mut runtime, ofstruct) = fixture(OFSTRUCT_BYTES, AccessRights::read_write());
    let retained = Win16HostFile(7);
    let state = runtime.win16.as_mut().unwrap();
    for number in super::FIRST_GUEST_HFILE..=super::LAST_GUEST_HFILE {
        state.files.insert(number, retained);
    }
    let count = state.files.len();
    let mut host = OpenFileHost::new(Ok(Win16HostOpenFile {
        result: 0, file: Some(HOST_FILE), ofstruct: vec![0; OFSTRUCT_BYTES],
    }));
    let return_to = prepare_gate(&mut runtime, 0xfff8_ffff, ofstruct, OF_REOPEN_VERIFY);
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_return(&runtime, 0xffff, return_to);
    assert_eq!(host.closed, [HOST_FILE]);
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.files.len(), count);
    assert!(state.files.values().all(|file| *file == retained));
}
