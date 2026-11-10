//! KERNEL drive and directory service gates. The host is a fake: these tests
//! lock the guest result and the bytes left in guest memory.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16CanonicalPath,
    Win16HostDiskSpace, Win16HostDriveKind, Win16HostFileSystemCall, Win16HostFileSystemOperation,
    Win16HostFileSystemPath, Win16HostFileSystemResult,
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
const DRIVE_C: u8 = b'C' - b'A';

struct VolumeHost {
    kinds: [Win16HostDriveKind; 26],
    drives: Vec<u16>,
    directory: bool,
    space: Win16HostDiskSpace,
    directories: Vec<ObservedPath>,
    spaces: Vec<ObservedPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedPath {
    canonical: bool,
    drive: u8,
    components: Vec<String>,
}

impl VolumeHost {
    fn new() -> Self {
        Self {
            kinds: [Win16HostDriveKind::MissingRoot; 26],
            drives: Vec::new(),
            directory: true,
            space: Win16HostDiskSpace {
                sectors_per_cluster: 8,
                bytes_per_sector: 512,
                free_clusters: 3,
                total_clusters: 9,
            },
            directories: Vec::new(),
            spaces: Vec::new(),
        }
    }
}

impl DosHost for VolumeHost {
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

impl RuntimeHost for VolumeHost {
    fn win16_drive_kind(&mut self, drive: u16) -> Result<Win16HostDriveKind, RuntimeError> {
        self.drives.push(drive);
        Ok(self.kinds[usize::from(drive)])
    }

    fn win16_file_system(
        &mut self, call: Win16HostFileSystemCall,
    ) -> Result<Win16HostFileSystemResult, RuntimeError> {
        match call.operation {
            Win16HostFileSystemOperation::NormalizePath { path, .. } => {
                let components = path.components.into_iter().map(|component| component.text).collect();
                Ok(Win16HostFileSystemResult::NormalizedPath(Some(Win16CanonicalPath {
                    drive: path.drive,
                    components,
                })))
            }
            Win16HostFileSystemOperation::QueryDirectory { path } => {
                self.directories.push(observe(&path));
                Ok(Win16HostFileSystemResult::Completed(self.directory))
            }
            Win16HostFileSystemOperation::GetDiskFreeSpace { path } => {
                self.spaces.push(observe(&path));
                Ok(Win16HostFileSystemResult::DiskSpace(Some(self.space)))
            }
            _ => panic!("unexpected file-system operation"),
        }
    }

    fn epoch_seconds(&self) -> i64 { 0 }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        Err(RuntimeError::new(Kind::CompatibilityGap, "no key"))
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { Ok(()) }
}

impl crate::RuntimeDdeHost for VolumeHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for VolumeHost {}
impl crate::RuntimeMidiHost for VolumeHost {}
impl crate::RuntimeNetbiosHost for VolumeHost {}

fn observe(path: &Win16HostFileSystemPath) -> ObservedPath {
    match path {
        Win16HostFileSystemPath::Guest(path) => ObservedPath {
            canonical: false,
            drive: path.drive,
            components: path.components.iter().map(|component| component.text.clone()).collect(),
        },
        Win16HostFileSystemPath::Canonical(path) => ObservedPath {
            canonical: true,
            drive: path.drive,
            components: path.components.clone(),
        },
    }
}

fn loaded_runtime(components: Vec<String>) -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\DRIVE.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.current_task_owner().unwrap();
    state.kernel_file_system.seed_owner(owner, Win16CanonicalPath {
        drive: DRIVE_C,
        components,
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

fn call(runtime: &mut Runtime, host: &mut VolumeHost, ordinal: u16, arguments: &[u8]) -> u16 {
    let stack = gate(runtime, ordinal, arguments);
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, host, 0,
    ).unwrap();
    stack
}

fn assert_word(runtime: &Runtime, stack: u16, popped: u16, ax: u16) {
    assert_eq!(runtime.cpu.regs.eax, (EAX_SENTINEL & 0xffff_0000) | u32::from(ax));
    assert_eq!(runtime.cpu.regs.edx, EDX_SENTINEL);
    assert_eq!(runtime.cpu.regs.sp(), stack.wrapping_add(4 + popped));
}

fn assert_dword(runtime: &Runtime, stack: u16, popped: u16, value: u32) {
    assert_eq!(runtime.cpu.regs.eax, (EAX_SENTINEL & 0xffff_0000) | (value & 0xffff));
    assert_eq!(runtime.cpu.regs.edx, (EDX_SENTINEL & 0xffff_0000) | (value >> 16));
    assert_eq!(runtime.cpu.regs.sp(), stack.wrapping_add(4 + popped));
}

fn read_at(runtime: &Runtime, offset: usize, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    runtime.memory.read_physical(PhysAddr(BASE + offset as u32), &mut bytes).unwrap();
    bytes
}

fn fixed_export(name: &[u8], ordinal: u16, pop: u16, kind: Win16ReturnKind) {
    let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    assert_eq!(lookup_export(b"KERNEL", ExportLookupTarget::Name(name)), Some(descriptor));
    assert_eq!(descriptor.return_kind, kind);
    assert_eq!(descriptor.calling_convention, ExportCallingConvention::Pascal);
    assert_eq!(descriptor.stack_cleanup, Win16ExportStackCleanup::Fixed(StackCleanup {
        callee_pop_bytes: pop,
        caller_pop_bytes: 0,
    }));
}

#[test]
fn drive_and_directory_exports_keep_their_win16_shapes() {
    fixed_export(b"GetDriveType", 136, 2, Win16ReturnKind::Word);
    fixed_export(b"GetCurrentDirectory", 411, 8, Win16ReturnKind::Dword);
    fixed_export(b"SetCurrentDirectory", 412, 4, Win16ReturnKind::Word);
    fixed_export(b"GetDiskFreeSpace", 422, 20, Win16ReturnKind::Word);
}

#[test]
fn get_drive_type_outside_a_through_z_cannot_be_determined() {
    let mut runtime = loaded_runtime(vec!["WORK".into()]);
    let mut host = VolumeHost::new();
    host.kinds[0] = Win16HostDriveKind::Fixed;
    host.kinds[1] = Win16HostDriveKind::MissingRoot;
    host.kinds[2] = Win16HostDriveKind::CdRom;

    let stack = call(&mut runtime, &mut host, 136, &26u16.to_le_bytes());
    assert_word(&runtime, stack, 2, 0);
    let stack = call(&mut runtime, &mut host, 136, &u16::MAX.to_le_bytes());
    assert_word(&runtime, stack, 2, 0);
    assert!(host.drives.is_empty());

    let stack = call(&mut runtime, &mut host, 136, &0u16.to_le_bytes());
    assert_word(&runtime, stack, 2, 3);
    let stack = call(&mut runtime, &mut host, 136, &1u16.to_le_bytes());
    assert_word(&runtime, stack, 2, 1);
    let stack = call(&mut runtime, &mut host, 136, &2u16.to_le_bytes());
    assert_word(&runtime, stack, 2, 4);
    assert_eq!(host.drives, [0, 1, 2]);
}

fn disk_buffer() -> (Vec<u8>, usize) {
    (vec![0xA5; 96], 32)
}

fn disk_outputs(selector: SelectorRef, output: u16) -> [u32; 4] {
    [0, 1, 2, 3].map(|index| far(selector, output + index * 4))
}

#[test]
fn get_disk_free_space_bare_drive_leaves_the_dwords_unchanged() {
    for path in [b"C:\0".as_slice(), b"c:\0".as_slice()] {
        let (mut bytes, output) = disk_buffer();
        bytes[..path.len()].copy_from_slice(path);
        let mut runtime = loaded_runtime(vec!["WORK".into()]);
        let selector = place(&mut runtime, &bytes);
        let mut host = VolumeHost::new();
        let outputs = disk_outputs(selector, output as u16);
        let arguments = pascal_arguments(&[
            &far(selector, 0).to_le_bytes(),
            &outputs[0].to_le_bytes(),
            &outputs[1].to_le_bytes(),
            &outputs[2].to_le_bytes(),
            &outputs[3].to_le_bytes(),
        ]);
        let stack = call(&mut runtime, &mut host, 422, &arguments);
        assert_word(&runtime, stack, 20, 0);
        assert!(host.directories.is_empty());
        assert!(host.spaces.is_empty());
        assert_eq!(read_at(&runtime, output, 16), vec![0xA5; 16]);
    }
}

#[test]
fn get_disk_free_space_non_directory_leaves_the_dwords_unchanged() {
    let (mut bytes, output) = disk_buffer();
    bytes[..13].copy_from_slice(b"C:\\NOTES.TXT\0");
    let mut runtime = loaded_runtime(vec!["WORK".into()]);
    let selector = place(&mut runtime, &bytes);
    let mut host = VolumeHost::new();
    host.directory = false;
    let outputs = disk_outputs(selector, output as u16);
    let arguments = pascal_arguments(&[
        &far(selector, 0).to_le_bytes(),
        &outputs[0].to_le_bytes(),
        &outputs[1].to_le_bytes(),
        &outputs[2].to_le_bytes(),
        &outputs[3].to_le_bytes(),
    ]);
    let stack = call(&mut runtime, &mut host, 422, &arguments);
    assert_word(&runtime, stack, 20, 0);
    assert_eq!(host.directories, [ObservedPath {
        canonical: false,
        drive: DRIVE_C,
        components: vec!["NOTES.TXT".into()],
    }]);
    assert!(host.spaces.is_empty());
    assert_eq!(read_at(&runtime, output, 16), vec![0xA5; 16]);
}

#[test]
fn get_disk_free_space_null_output_leaves_the_dwords_unchanged() {
    let (mut bytes, output) = disk_buffer();
    bytes[..4].copy_from_slice(b"C:\\\0");
    let mut runtime = loaded_runtime(vec!["WORK".into()]);
    let selector = place(&mut runtime, &bytes);
    let mut host = VolumeHost::new();
    let outputs = disk_outputs(selector, output as u16);
    let arguments = pascal_arguments(&[
        &far(selector, 0).to_le_bytes(),
        &outputs[0].to_le_bytes(),
        &0u32.to_le_bytes(),
        &outputs[2].to_le_bytes(),
        &outputs[3].to_le_bytes(),
    ]);
    let stack = call(&mut runtime, &mut host, 422, &arguments);
    assert_word(&runtime, stack, 20, 0);
    assert!(host.directories.is_empty());
    assert!(host.spaces.is_empty());
    assert_eq!(read_at(&runtime, output, 16), vec![0xA5; 16]);
}

#[test]
fn get_disk_free_space_null_root_uses_the_current_drive_root() {
    let (bytes, output) = disk_buffer();
    let mut runtime = loaded_runtime(vec!["WORK".into()]);
    let selector = place(&mut runtime, &bytes);
    let mut host = VolumeHost::new();
    let outputs = disk_outputs(selector, output as u16);
    let arguments = pascal_arguments(&[
        &0u32.to_le_bytes(),
        &outputs[0].to_le_bytes(),
        &outputs[1].to_le_bytes(),
        &outputs[2].to_le_bytes(),
        &outputs[3].to_le_bytes(),
    ]);
    let stack = call(&mut runtime, &mut host, 422, &arguments);
    assert_word(&runtime, stack, 20, 1);
    let root = ObservedPath { canonical: true, drive: DRIVE_C, components: Vec::new() };
    assert_eq!(host.directories, [root.clone()]);
    assert_eq!(host.spaces, [root]);
    assert_eq!(read_at(&runtime, output, 16), expected_space());
}

#[test]
fn get_disk_free_space_writes_directory_geometry() {
    let (mut bytes, output) = disk_buffer();
    bytes[..8].copy_from_slice(b"C:\\WORK\0");
    let mut runtime = loaded_runtime(vec!["WORK".into()]);
    let selector = place(&mut runtime, &bytes);
    let mut host = VolumeHost::new();
    let outputs = disk_outputs(selector, output as u16);
    let arguments = pascal_arguments(&[
        &far(selector, 0).to_le_bytes(),
        &outputs[0].to_le_bytes(),
        &outputs[1].to_le_bytes(),
        &outputs[2].to_le_bytes(),
        &outputs[3].to_le_bytes(),
    ]);
    let stack = call(&mut runtime, &mut host, 422, &arguments);
    assert_word(&runtime, stack, 20, 1);
    assert_eq!(host.spaces, [ObservedPath {
        canonical: false,
        drive: DRIVE_C,
        components: vec!["WORK".into()],
    }]);
    assert_eq!(read_at(&runtime, output, 16), expected_space());
}

fn expected_space() -> Vec<u8> {
    let space = Win16HostDiskSpace {
        sectors_per_cluster: 8,
        bytes_per_sector: 512,
        free_clusters: 3,
        total_clusters: 9,
    };
    [
        space.sectors_per_cluster,
        space.bytes_per_sector,
        space.free_clusters,
        space.total_clusters,
    ].into_iter().flat_map(u32::to_le_bytes).collect()
}

#[test]
fn current_directory_preserves_text_unless_the_new_directory_exists() {
    let mut bytes = vec![0xA5; 96];
    bytes[..8].copy_from_slice(b"C:\\NOPE\0");
    bytes[16..25].copy_from_slice(b"C:\\OTHER\0");
    let mut runtime = loaded_runtime(vec!["WORK".into()]);
    let selector = place(&mut runtime, &bytes);
    let mut host = VolumeHost::new();
    let output = far(selector, 48);

    let stack = call(&mut runtime, &mut host, 411, &pascal_arguments(&[
        &2u32.to_le_bytes(), &output.to_le_bytes(),
    ]));
    assert_dword(&runtime, stack, 8, 8);
    assert_eq!(read_at(&runtime, 48, 16), vec![0xA5; 16]);

    host.directory = false;
    let stack = call(&mut runtime, &mut host, 412, &far(selector, 0).to_le_bytes());
    assert_word(&runtime, stack, 4, 0);

    let stack = call(&mut runtime, &mut host, 411, &pascal_arguments(&[
        &32u32.to_le_bytes(), &output.to_le_bytes(),
    ]));
    assert_dword(&runtime, stack, 8, 7);
    let mut kept = vec![0xA5; 16];
    kept[..8].copy_from_slice(b"C:\\WORK\0");
    assert_eq!(read_at(&runtime, 48, 16), kept);

    host.directory = true;
    let stack = call(&mut runtime, &mut host, 412, &far(selector, 16).to_le_bytes());
    assert_word(&runtime, stack, 4, 1);
    let stack = call(&mut runtime, &mut host, 411, &pascal_arguments(&[
        &32u32.to_le_bytes(), &output.to_le_bytes(),
    ]));
    assert_dword(&runtime, stack, 8, 8);
    let mut moved = vec![0xA5; 16];
    moved[..9].copy_from_slice(b"C:\\OTHER\0");
    assert_eq!(read_at(&runtime, 48, 16), moved);

    let mut root_runtime = loaded_runtime(Vec::new());
    let root_bytes = vec![0xA5; 32];
    let root_selector = place(&mut root_runtime, &root_bytes);
    let root_output = far(root_selector, 0);
    let stack = call(&mut root_runtime, &mut host, 411, &pascal_arguments(&[
        &8u32.to_le_bytes(), &root_output.to_le_bytes(),
    ]));
    assert_dword(&root_runtime, stack, 8, 3);
    let mut root = vec![0xA5; 8];
    root[..4].copy_from_slice(b"C:\\\0");
    assert_eq!(read_at(&root_runtime, 0, 8), root);
}
