//! KERNEL.92 service-gate and drive-type boundary checks. No host writes.

use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost,
    Win16CanonicalPath, Win16HostDriveKind};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};
use guest_core::{OwnerId, Selector};
use win16_abi::{ExportLookupTarget, Win16KernelPathInfoRequest, lookup_export};

struct DriveHost {
    kinds: [Win16HostDriveKind; 26],
    queried: Vec<u16>,
    failure: Option<u16>,
}

impl Default for DriveHost {
    fn default() -> Self {
        Self { kinds: [Win16HostDriveKind::MissingRoot; 26], queried: Vec::new(), failure: None }
    }
}

impl DosHost for DriveHost {
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

impl RuntimeHost for DriveHost {
    fn win16_drive_kind(&mut self, drive: u16) -> Result<Win16HostDriveKind, RuntimeError> {
        self.queried.push(drive);
        if self.failure == Some(drive) {
            return Err(RuntimeError::new(Kind::HostFailure, "test drive query failure"));
        }
        Ok(self.kinds[usize::from(drive)])
    }
    fn win16_path_info(&mut self, _operation: crate::Win16HostPathInfoOperation)
        -> Result<crate::Win16HostPathInfoResult, RuntimeError> {
        panic!("GetTempDrive must not consult native TEMP or create a temporary file")
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for DriveHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for DriveHost {}
impl crate::RuntimeMidiHost for DriveHost {}
impl crate::RuntimeNetbiosHost for DriveHost {}

fn fixture(current_drive: u8) -> Runtime {
    // Reuse the existing service-gate fixture; this test adds no NE generator.
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TEMPDRV.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let owner = state.current_task_owner().unwrap();
    state.kernel_file_system.seed_owner(owner,
        Win16CanonicalPath { drive: current_drive, components: vec!["WORK".into()] }).unwrap();
    runtime
}

fn query(runtime: &mut Runtime, drive: u8, host: &mut impl RuntimeHost) -> Result<u32, RuntimeError> {
    runtime.win16.as_ref().unwrap().execute_kernel_path_info(
        Win16KernelPathInfoRequest::GetTempDrive { drive }, &mut runtime.memory, host)
}

fn prepare_gate(runtime: &mut Runtime, argument: u16) -> (u16, u16, u16, Vec<u8>) {
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let mut bytes = Vec::from(return_ip.to_le_bytes());
    bytes.extend_from_slice(&return_cs.to_le_bytes());
    bytes.extend_from_slice(&argument.to_le_bytes());
    bytes.extend_from_slice(&[0xa1, 0xb2]);
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(
        lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(92)).unwrap()));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    (return_cs, return_ip, stack + 6, bytes)
}

fn stack_bytes(runtime: &Runtime, stack: u16) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    let mut bytes = vec![0; 8];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

#[test]
fn get_temp_drive_gate_returns_byte_and_observed_ah_with_one_word_cleanup() {
    let mut runtime = fixture(7);
    let (cs, ip, sp, bytes) = prepare_gate(&mut runtime, 0xffe6); // 'f' | TF_FORCEDRIVE
    let preserved = (runtime.cpu.regs.ds, runtime.cpu.regs.ss,
        runtime.cpu.regs.ebp, runtime.cpu.regs.esi, runtime.cpu.regs.edi);
    assert_eq!(runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0).unwrap(), None);
    assert_eq!(runtime.cpu.regs.ax(), 0x3a46);
    // DX is not a public result. The runtime's Word return leaves it alone.
    assert_eq!(runtime.cpu.regs.dx(), 0x5aa5);
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), (cs, ip, sp));
    assert_eq!((runtime.cpu.regs.ds, runtime.cpu.regs.ss,
        runtime.cpu.regs.ebp, runtime.cpu.regs.esi, runtime.cpu.regs.edi), preserved);
    assert_eq!(stack_bytes(&runtime, sp - 6), bytes);
}

#[test]
fn get_temp_drive_current_selection_is_per_task_and_does_not_change_directories() {
    let mut runtime = fixture(7);
    let first = runtime.win16.as_ref().unwrap().current_task_owner().unwrap();
    let second = OwnerId(0x1234);
    {
        let state = runtime.win16.as_mut().unwrap();
        state.tasks.create(second, Some(first)).unwrap();
        state.kernel_file_system.seed_owner(second,
            Win16CanonicalPath { drive: 24, components: vec!["OTHER".into()] }).unwrap();
        state.kernel_file_system.record_dos_current_drive(second, 25).unwrap();
    }
    let mut host = DriveHost::default();
    for (owner, current) in [(first, 7), (second, 25), (first, 7)] {
        runtime.win16.as_mut().unwrap().tasks.dispatch(owner).unwrap();
        for drive in [0, 0x80] {
            assert_eq!(query(&mut runtime, drive, &mut host).unwrap(),
                u32::from(u16::from_le_bytes([b'A' + current, b':'])));
            assert_eq!(runtime.win16.as_ref().unwrap().kernel_file_system.current_drive(owner).unwrap(), current);
        }
    }
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.kernel_file_system.directory_for_drive(first, 7).unwrap().unwrap().components, ["WORK"]);
    assert_eq!(state.kernel_file_system.directory_for_drive(second, 24).unwrap().unwrap().components, ["OTHER"]);
    assert!(state.kernel_file_system.directory_for_drive(second, 25).unwrap().is_none());
    assert_eq!(host.queried, (0..26).cycle().take(78).collect::<Vec<_>>());
}

#[test]
fn get_drive_type_returns_one_when_the_root_is_missing() {
    let runtime = fixture(7);
    let state = runtime.win16.as_ref().unwrap();
    let cases = [
        (Win16HostDriveKind::Unknown, 0),
        (Win16HostDriveKind::MissingRoot, 1),
        (Win16HostDriveKind::Removable, 2),
        (Win16HostDriveKind::Fixed, 3),
        (Win16HostDriveKind::RamDisk, 3),
        (Win16HostDriveKind::Remote, 4),
        (Win16HostDriveKind::CdRom, 4),
    ];
    for (drive, (kind, expected)) in cases.into_iter().enumerate() {
        let mut host = DriveHost::default();
        let drive = u16::try_from(drive).unwrap();
        host.kinds[usize::from(drive)] = kind;
        assert_eq!(state.drive_type(drive, &mut host).unwrap(), expected);
        assert_eq!(host.queried, [drive]);
    }
}

#[test]
fn get_temp_drive_uses_existing_fixed_and_ram_disk_classification_only() {
    for selected_kind in [Win16HostDriveKind::Fixed, Win16HostDriveKind::RamDisk] {
        let mut runtime = fixture(25);
        let mut host = DriveHost::default();
        host.kinds[..8].copy_from_slice(&[
            Win16HostDriveKind::Removable, Win16HostDriveKind::Remote,
            Win16HostDriveKind::MissingRoot, Win16HostDriveKind::Unknown,
            Win16HostDriveKind::CdRom, selected_kind,
            Win16HostDriveKind::Fixed, Win16HostDriveKind::RamDisk,
        ]);
        assert_eq!(query(&mut runtime, b'h', &mut host).unwrap(), 0x3a46);
        assert_eq!(host.queried, [0, 1, 2, 3, 4, 5]);
        let state = runtime.win16.as_ref().unwrap();
        assert_eq!(state.kernel_file_system.current_drive(state.current_task_owner().unwrap()).unwrap(), 25);
    }
}

#[test]
fn get_temp_drive_missing_fixed_media_returns_requested_letter_even_if_unmounted() {
    let mut runtime = fixture(7);
    let mut host = DriveHost::default();
    for (request, expected) in [(b'q', 0x3a51), (b'q' | 0x80, 0x3a51), (0xb1, 0x3a11), (0xe0, 0x3a40)] {
        assert_eq!(query(&mut runtime, request, &mut host).unwrap(), expected);
    }
    assert_eq!(host.queried, (0..26).collect::<Vec<_>>());
}

#[test]
fn get_temp_drive_probe_error_does_not_return_fallback_or_commit_frame() {
    let mut runtime = fixture(7);
    let (_, _, sp, bytes) = prepare_gate(&mut runtime, b'd' as u16);
    let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
    let mut host = DriveHost { failure: Some(2), ..DriveHost::default() };
    let error = runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0).unwrap_err();
    assert_eq!(error.kind(), Kind::HostFailure);
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0xa55a, 0x5aa5));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
    assert_eq!(stack_bytes(&runtime, sp - 6), bytes);
    assert_eq!(host.queried, [0, 1, 2]);
}

#[test]
fn get_temp_drive_unseeded_current_drive_is_an_error_without_host_guessing() {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TEMPDRV.NE").unwrap();
    let mut host = DriveHost::default();
    for requested in [0, 0x80] {
        assert_eq!(query(&mut runtime, requested, &mut host).unwrap_err().kind(), Kind::InternalInvariant);
    }
    assert!(host.queried.is_empty());
    assert_eq!(query(&mut runtime, b'x' | 0x80, &mut host).unwrap(), 0x3a58);
}
