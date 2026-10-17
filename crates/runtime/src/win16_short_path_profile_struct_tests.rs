//! Service-gate checks for KERNEL.274, KERNEL.406, and KERNEL.407.
//! The host is a fake: these tests lock the guest contract, not a Windows volume.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16CanonicalPath,
    Win16HostFileSystemCall, Win16HostFileSystemOperation, Win16HostFileSystemResult,
    Win16ProfilePath,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::{PhysAddr, Selector};
use win16_abi::{
    AccessRights, ExportCallingConvention, ExportLookupTarget, SegmentedPointer, SelectorRef,
    StackCleanup, Win16ExportStackCleanup, Win16ReturnKind, lookup_export,
};

const BASE: u32 = 0x80000;
const EAX_SENTINEL: u32 = 0x1357_a55a;
const EDX_SENTINEL: u32 = 0x2468_5aa5;
const SHORT: &[u8] = b"C:\\LONGFI~1.TXT";

struct ProbeHost {
    missing: bool,
    short_path: Option<Vec<u8>>,
    short_calls: u32,
    normalize_calls: u32,
    writes: Vec<ProfileCall>,
    reads: u32,
    read_result: (bool, Vec<u8>),
}

struct ProfileCall {
    section: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
    data_size: u16,
    path: &'static str,
}

impl ProbeHost {
    fn new() -> Self {
        Self {
            missing: false,
            short_path: Some(SHORT.to_vec()),
            short_calls: 0,
            normalize_calls: 0,
            writes: Vec::new(),
            reads: 0,
            read_result: (false, Vec::new()),
        }
    }
}

impl DosHost for ProbeHost {
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
    fn guest_code_page(&self) -> text_codec::CodePage { text_codec::CodePage::CP437 }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { panic!("unexpected host call") }
}

impl RuntimeHost for ProbeHost {
    fn win16_file_system(
        &mut self, call: Win16HostFileSystemCall,
    ) -> Result<Win16HostFileSystemResult, RuntimeError> {
        match call.operation {
            Win16HostFileSystemOperation::NormalizePath { path, .. } => {
                self.normalize_calls += 1;
                if self.missing {
                    return Ok(Win16HostFileSystemResult::NormalizedPath(None));
                }
                let components = path.components.into_iter().map(|component| component.text).collect();
                Ok(Win16HostFileSystemResult::NormalizedPath(Some(Win16CanonicalPath {
                    drive: path.drive,
                    components,
                })))
            }
            Win16HostFileSystemOperation::ShortPath { path } => {
                self.short_calls += 1;
                assert_eq!(path.drive, b'C' - b'A');
                assert_eq!(path.components, ["LONGFILE.TXT"]);
                Ok(Win16HostFileSystemResult::ShortPath(self.short_path.clone()))
            }
            _ => panic!("unexpected file-system operation"),
        }
    }
    fn win16_profile_struct_write(
        &mut self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        data: Option<&[u8]>,
        data_size: u16,
        filename: &Win16ProfilePath,
    ) -> Result<bool, RuntimeError> {
        self.writes.push(ProfileCall {
            section: section.map(|bytes| bytes.to_vec()),
            key: key.map(|bytes| bytes.to_vec()),
            data: data.map(|bytes| bytes.to_vec()),
            data_size,
            path: profile_label(filename),
        });
        Ok(true)
    }
    fn win16_profile_struct_read(
        &mut self,
        section: Option<&[u8]>,
        key: Option<&[u8]>,
        capacity: u16,
        filename: &Win16ProfilePath,
    ) -> Result<(bool, Vec<u8>), RuntimeError> {
        assert_eq!(section, Some(b"sec".as_slice()));
        assert_eq!(key, Some(b"key".as_slice()));
        assert_eq!(profile_label(filename), "windows");
        assert!(self.read_result.1.len() == usize::from(capacity) || !self.read_result.0);
        self.reads += 1;
        Ok(self.read_result.clone())
    }
    fn epoch_seconds(&self) -> i64 { 0 }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        Err(RuntimeError::new(Kind::CompatibilityGap, "no key"))
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { Ok(()) }
}
impl crate::RuntimeDdeHost for ProbeHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for ProbeHost {}
impl crate::RuntimeMidiHost for ProbeHost {}
impl crate::RuntimeNetbiosHost for ProbeHost {}

fn profile_label(path: &Win16ProfilePath) -> &'static str {
    match path {
        Win16ProfilePath::System => "system",
        Win16ProfilePath::WindowsDirectory(name) if name == "APP.INI" => "windows",
        Win16ProfilePath::Invalid => "invalid",
        _ => "other",
    }
}

fn loaded_runtime() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\PROFILE.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.current_task_owner().unwrap();
    state.kernel_file_system.seed_owner(owner, Win16CanonicalPath {
        drive: b'C' - b'A',
        components: vec!["WORK".into()],
    }).unwrap();
    runtime
}

fn place(runtime: &mut Runtime, bytes: &[u8]) -> SelectorRef {
    runtime.memory.write_physical(PhysAddr(BASE), bytes).unwrap();
    runtime.win16.as_mut().unwrap().selectors.alloc_block(
        PhysAddr(BASE), bytes.len() as u32, AccessRights::read_write(), &runtime.memory,
    ).unwrap()
}

fn far(selector: SelectorRef, offset: u16) -> u32 {
    SegmentedPointer::new(selector, offset).far_value()
}

/// Pascal places the last argument nearest the return address.
fn pascal_arguments(slots: &[&[u8]]) -> Vec<u8> {
    let mut arguments = Vec::new();
    for slot in slots.iter().rev() {
        arguments.extend_from_slice(slot);
    }
    arguments
}

fn gate(runtime: &mut Runtime, ordinal: u16, arguments: &[u8]) -> u16 {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_ip = 0x12_u16;
    let return_cs = runtime.cpu.regs.cs;
    let stack = runtime.cpu.regs.sp();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    frame.extend_from_slice(arguments);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &frame).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.eax = EAX_SENTINEL;
    runtime.cpu.regs.edx = EDX_SENTINEL;
    stack
}

fn assert_word(runtime: &Runtime, stack: u16, popped: u16, ax: u16) {
    assert_eq!(runtime.cpu.regs.eax, (EAX_SENTINEL & 0xffff_0000) | u32::from(ax));
    assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
    assert_eq!(runtime.cpu.regs.sp(), stack + 4 + popped);
}

fn read_at(runtime: &Runtime, offset: usize, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    runtime.memory.read_physical(PhysAddr(BASE + offset as u32), &mut bytes).unwrap();
    bytes
}

#[test]
fn get_short_path_name_is_a_ten_byte_word_pascal_export() {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(274)).unwrap();
    assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Name(b"GetShortPathName")), Some(descriptor));
    assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: 10, caller_pop_bytes: 0,
    }));
    assert_eq!(descriptor.parameters.len(), 3);
}

#[test]
fn get_short_path_name_writes_the_ansi_short_path_and_returns_its_length() {
    let mut bytes = vec![0xA5; 96];
    bytes[..16].copy_from_slice(b"C:\\LONGFILE.TXT\0");
    let mut runtime = loaded_runtime();
    let selector = place(&mut runtime, &bytes);
    let path = far(selector, 0).to_le_bytes();
    let output = far(selector, 64).to_le_bytes();
    let capacity = 32_u16.to_le_bytes();
    let stack = gate(&mut runtime, 274, &pascal_arguments(&[&path, &output, &capacity]));
    let mut host = ProbeHost::new();
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_word(&runtime, stack, 10, SHORT.len() as u16);
    let mut expected = vec![0xA5; 32];
    expected[..SHORT.len()].copy_from_slice(SHORT);
    expected[SHORT.len()] = 0;
    assert_eq!(read_at(&runtime, 64, 32), expected);
    assert_eq!(host.short_calls, 1);
    assert_eq!(host.normalize_calls, 1);
}

#[test]
fn get_short_path_name_reports_the_required_size_without_writing() {
    let mut bytes = vec![0xA5; 96];
    bytes[..16].copy_from_slice(b"C:\\LONGFILE.TXT\0");
    let mut runtime = loaded_runtime();
    let selector = place(&mut runtime, &bytes);
    let path = far(selector, 0).to_le_bytes();
    let output = far(selector, 64).to_le_bytes();
    let capacity = 4_u16.to_le_bytes();
    let stack = gate(&mut runtime, 274, &pascal_arguments(&[&path, &output, &capacity]));
    let mut host = ProbeHost::new();
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_word(&runtime, stack, 10, (SHORT.len() + 1) as u16);
    assert_eq!(read_at(&runtime, 64, 32), vec![0xA5; 32]);
}

#[test]
fn get_short_path_name_null_or_missing_path_returns_zero() {
    let bytes = vec![0xA5; 96];
    let mut runtime = loaded_runtime();
    let selector = place(&mut runtime, &bytes);
    let path = 0_u32.to_le_bytes();
    let output = far(selector, 64).to_le_bytes();
    let capacity = 32_u16.to_le_bytes();
    let stack = gate(&mut runtime, 274, &pascal_arguments(&[&path, &output, &capacity]));
    let mut host = ProbeHost::new();
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_word(&runtime, stack, 10, 0);
    assert_eq!(host.normalize_calls, 0);
    assert_eq!(read_at(&runtime, 64, 32), vec![0xA5; 32]);

    let mut bytes = vec![0xA5; 96];
    bytes[..16].copy_from_slice(b"C:\\LONGFILE.TXT\0");
    let mut runtime = loaded_runtime();
    let selector = place(&mut runtime, &bytes);
    let path = far(selector, 0).to_le_bytes();
    let output = far(selector, 64).to_le_bytes();
    let capacity = 32_u16.to_le_bytes();
    let stack = gate(&mut runtime, 274, &pascal_arguments(&[&path, &output, &capacity]));
    let mut host = ProbeHost::new();
    host.missing = true;
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_word(&runtime, stack, 10, 0);
    assert_eq!(host.short_calls, 0);
    assert_eq!(read_at(&runtime, 64, 32), vec![0xA5; 32]);
}

#[test]
fn private_profile_struct_exports_are_eighteen_byte_word_calls() {
    for (ordinal, name) in [
        (406, &b"WritePrivateProfileStruct"[..]),
        (407, &b"GetPrivateProfileStruct"[..]),
    ] {
        let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
        assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Name(name)), Some(descriptor));
        assert_eq!(descriptor.return_kind, Win16ReturnKind::Word);
        assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
            callee_pop_bytes: 18, caller_pop_bytes: 0,
        }));
    }
}

#[test]
fn write_private_profile_struct_forwards_opaque_bytes_for_a_bare_ini_name() {
    let mut bytes = vec![0xA5; 80];
    bytes[..4].copy_from_slice(b"sec\0");
    bytes[16..20].copy_from_slice(b"key\0");
    bytes[32..36].copy_from_slice(&[1, 2, 3, 4]);
    bytes[48..56].copy_from_slice(b"APP.INI\0");
    let mut runtime = loaded_runtime();
    let selector = place(&mut runtime, &bytes);
    let section = far(selector, 0).to_le_bytes();
    let key = far(selector, 16).to_le_bytes();
    let data = far(selector, 32).to_le_bytes();
    let data_size = 4_u16.to_le_bytes();
    let filename = far(selector, 48).to_le_bytes();
    let stack = gate(
        &mut runtime,
        406,
        &pascal_arguments(&[&section, &key, &data, &data_size, &filename]),
    );
    let mut host = ProbeHost::new();
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_word(&runtime, stack, 18, 1);
    assert_eq!(host.writes.len(), 1);
    let call = &host.writes[0];
    assert_eq!(call.section.as_deref(), Some(b"sec".as_slice()));
    assert_eq!(call.key.as_deref(), Some(b"key".as_slice()));
    assert_eq!(call.data.as_deref(), Some([1, 2, 3, 4].as_slice()));
    assert_eq!(call.data_size, 4);
    assert_eq!(call.path, "windows");
}

#[test]
fn write_private_profile_struct_null_key_does_not_read_the_payload() {
    let mut bytes = vec![0xA5; 64];
    bytes[..4].copy_from_slice(b"sec\0");
    bytes[16..24].copy_from_slice(b"APP.INI\0");
    let mut runtime = loaded_runtime();
    let selector = place(&mut runtime, &bytes);
    let section = far(selector, 0).to_le_bytes();
    let key = 0_u32.to_le_bytes();
    let data = 0_u32.to_le_bytes();
    let data_size = 4_u16.to_le_bytes();
    let filename = far(selector, 16).to_le_bytes();
    let stack = gate(
        &mut runtime,
        406,
        &pascal_arguments(&[&section, &key, &data, &data_size, &filename]),
    );
    let mut host = ProbeHost::new();
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_word(&runtime, stack, 18, 1);
    assert!(host.writes[0].key.is_none());
    assert!(host.writes[0].data.is_none());
    assert_eq!(host.writes[0].data_size, 4);
    assert_eq!(host.writes[0].path, "windows");
}

#[test]
fn get_private_profile_struct_writes_only_when_the_host_accepts_the_bytes() {
    let mut bytes = vec![0xA5; 80];
    bytes[..4].copy_from_slice(b"sec\0");
    bytes[16..20].copy_from_slice(b"key\0");
    bytes[48..56].copy_from_slice(b"APP.INI\0");
    let mut runtime = loaded_runtime();
    let selector = place(&mut runtime, &bytes);
    let section = far(selector, 0).to_le_bytes();
    let key = far(selector, 16).to_le_bytes();
    let data = far(selector, 32).to_le_bytes();
    let data_size = 4_u16.to_le_bytes();
    let filename = far(selector, 48).to_le_bytes();
    let arguments = pascal_arguments(&[&section, &key, &data, &data_size, &filename]);
    let stack = gate(&mut runtime, 407, &arguments);
    let mut host = ProbeHost::new();
    host.read_result = (true, vec![9, 8, 7, 6]);
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_word(&runtime, stack, 18, 1);
    assert_eq!(read_at(&runtime, 32, 4), [9, 8, 7, 6]);
    assert_eq!(host.reads, 1);

    let mut runtime = loaded_runtime();
    let selector = place(&mut runtime, &bytes);
    let section = far(selector, 0).to_le_bytes();
    let key = far(selector, 16).to_le_bytes();
    let data = far(selector, 32).to_le_bytes();
    let data_size = 4_u16.to_le_bytes();
    let filename = far(selector, 48).to_le_bytes();
    let stack = gate(
        &mut runtime,
        407,
        &pascal_arguments(&[&section, &key, &data, &data_size, &filename]),
    );
    let mut host = ProbeHost::new();
    host.read_result = (false, Vec::new());
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_word(&runtime, stack, 18, 0);
    assert_eq!(read_at(&runtime, 32, 4), [0xA5, 0xA5, 0xA5, 0xA5]);
}

#[test]
fn get_private_profile_struct_null_output_returns_false_without_the_host() {
    let mut bytes = vec![0xA5; 64];
    bytes[..4].copy_from_slice(b"sec\0");
    bytes[16..20].copy_from_slice(b"key\0");
    bytes[32..40].copy_from_slice(b"APP.INI\0");
    let mut runtime = loaded_runtime();
    let selector = place(&mut runtime, &bytes);
    let section = far(selector, 0).to_le_bytes();
    let key = far(selector, 16).to_le_bytes();
    let data = 0_u32.to_le_bytes();
    let data_size = 4_u16.to_le_bytes();
    let filename = far(selector, 32).to_le_bytes();
    let stack = gate(
        &mut runtime,
        407,
        &pascal_arguments(&[&section, &key, &data, &data_size, &filename]),
    );
    let mut host = ProbeHost::new();
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0,
    ).unwrap();
    assert_word(&runtime, stack, 18, 0);
    assert_eq!(host.reads, 0);
}
