//! Protected DOS create-new routing through the actual Win16 caller adapter.

use super::dispatch_int21;
use super::super::test_support::tiny_ne_executable;
use crate::{Runtime, RuntimeError, RuntimeHost, Win16CanonicalPath};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosAction, DosDirectoryEntry, DosErrorCode, DosFileAccess, DosFileSharing,
    DosFileStatus, DosHost, DosHostError, DosHostFile, DosHostSearch,
    DosIoctlObjectInfo, DosSeekOrigin,
};
use guest_core::{OwnerId, Selector};

#[derive(Default)]
struct CreateNewHost {
    active: Option<(OwnerId, Win16CanonicalPath)>,
    calls: Vec<(OwnerId, Win16CanonicalPath, Vec<u8>, u8)>,
    files: Vec<(DosHostFile, Win16CanonicalPath, Vec<u8>, u8)>,
}

impl DosHost for CreateNewHost {
    fn file_create_new(&mut self, path: &[u8], attributes: u8) -> Result<DosHostFile, DosHostError> {
        let (owner, directory) = self.active.clone().expect("task directory must be activated first");
        self.calls.push((owner, directory.clone(), path.to_vec(), attributes));
        if self.files.iter().any(|entry| entry.1 == directory && entry.2 == path) {
            return Err(DosHostError::new(DosErrorCode::FileExists));
        }
        let file = DosHostFile(self.files.len() as u64 + 1);
        self.files.push((file, directory, path.to_vec(), attributes));
        Ok(file)
    }
    fn file_ioctl_info(&self, file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        let entry = self.files.iter().find(|entry| entry.0 == file)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        Ok(DosIoctlObjectInfo::File { drive: entry.1.drive, written: false })
    }
    fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        let entry = self.files.iter().find(|entry| entry.0 == file)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        assert_eq!(entry.2, b"SHARED.DAT");
        Ok(DosFileStatus {
            short_name: *b"SHARED  DAT", size: 0, position: 0,
            attributes: entry.3, write_time: 0, write_date: 0,
        })
    }
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, _path: &[u8], _access: DosFileAccess) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open_with_sharing(&mut self, _path: &[u8], _access: DosFileAccess, _sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        let index = self.files.iter().position(|entry| entry.0 == file)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        self.files.remove(index);
        Ok(())
    }
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
    fn guest_code_page(&self) -> text_codec::CodePage { text_codec::CodePage::Cp437 }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { 3 }
}

impl RuntimeHost for CreateNewHost {
    fn activate_win16_dos_directory(
        &mut self, owner: OwnerId, path: &Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        self.active = Some((owner, path.clone()));
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for CreateNewHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for CreateNewHost {}
impl crate::RuntimeMidiHost for CreateNewHost {}
impl crate::RuntimeNetbiosHost for CreateNewHost {}

fn fixture() -> Runtime {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\CREATE.NE").unwrap();
    let state = runtime.win16.as_mut().unwrap();
    state.tasks.create(OwnerId(2), Some(OwnerId(1))).unwrap();
    for (owner, directory) in [(OwnerId(1), "TASK_A"), (OwnerId(2), "TASK_B")] {
        state.kernel_file_system.seed_owner(owner, Win16CanonicalPath {
            drive: 2, components: vec![directory.to_owned()],
        }).unwrap();
    }
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x20).unwrap();
    let address = state.selectors.translate(pointer, win16_abi::Access::Read, 11, &runtime.memory).unwrap();
    assert_ne!(address, guest_core::real_address(runtime.cpu.regs.ds, 0x20));
    state.selectors.write(&mut runtime.memory, pointer, b"SHARED.DAT\0").unwrap();
    runtime
}

fn call(runtime: &mut Runtime, host: &mut CreateNewHost, owner: OwnerId) -> Result<DosAction, RuntimeError> {
    let state = runtime.win16.as_mut().unwrap();
    state.tasks.dispatch(owner).unwrap();
    runtime.cpu.regs.set_ax(0x5b00);
    runtime.cpu.regs.set_cx(2);
    runtime.cpu.regs.set_dx(0x20);
    dispatch_int21(state, &mut runtime.dos, &mut runtime.cpu.regs, &mut runtime.memory, host)
}

#[test]
fn create_new_protected_pointer_and_directory_follow_the_current_task() {
    let mut runtime = fixture();
    let mut host = CreateNewHost::default();
    let selector = runtime.cpu.regs.ds;
    for owner in [OwnerId(1), OwnerId(2)] {
        assert_eq!(call(&mut runtime, &mut host, owner).unwrap(), DosAction::Continue);
        assert!(!runtime.cpu.regs.carry());
        assert_eq!(runtime.cpu.regs.ds, selector);
    }
    assert_eq!(host.files.len(), 2);
    assert_eq!(host.calls[0], (OwnerId(1), Win16CanonicalPath {
        drive: 2, components: vec!["TASK_A".to_owned()],
    }, b"SHARED.DAT".to_vec(), 2));
    assert_eq!(host.calls[1], (OwnerId(2), Win16CanonicalPath {
        drive: 2, components: vec!["TASK_B".to_owned()],
    }, b"SHARED.DAT".to_vec(), 2));
    // Returning to task A must reactivate A's cwd, rather than reusing B's
    // most recently installed host context. Its original name now collides.
    assert_eq!(call(&mut runtime, &mut host, OwnerId(1)).unwrap(), DosAction::Continue);
    assert!(runtime.cpu.regs.carry());
    assert_eq!(runtime.cpu.regs.ax(), 80);
    assert_eq!(host.calls[2], host.calls[0]);
    assert_eq!(host.files.len(), 2);
    runtime.dos.close_all_handles_checked(&mut host).unwrap();
    assert!(host.files.is_empty());
}

#[test]
fn create_new_protected_invalid_selector_never_reaches_file_creation() {
    let mut runtime = fixture();
    let mut host = CreateNewHost::default();
    runtime.cpu.regs.ds = 0;
    let error = call(&mut runtime, &mut host, OwnerId(1)).unwrap_err();
    assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault);
    assert!(host.calls.is_empty());
    assert!(host.files.is_empty());
}
