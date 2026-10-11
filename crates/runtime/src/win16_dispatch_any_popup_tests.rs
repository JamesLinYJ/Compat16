//! USER.52 real service-gate tests: canonical BOOL, zero arguments, and errors.
use super::super::{ImportBinding, test_support::{NoHost, tiny_ne_executable}};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError,
    DosHostFile, DosHostSearch, DosSeekOrigin};
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, lookup_export};

struct PopupHost { result: bool, calls: usize, fail: bool }
impl DosHost for PopupHost {
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


impl RuntimeHost for PopupHost {
    fn win16_any_popup(&mut self) -> Result<bool, RuntimeError> {
        self.calls += 1;
        if self.fail { Err(RuntimeError::new(Kind::HostFailure, "AnyPopup test failure")) }
        else { Ok(self.result) }
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for PopupHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for PopupHost {}
impl crate::RuntimeMidiHost for PopupHost {}
impl crate::RuntimeNetbiosHost for PopupHost {}

fn prepare() -> (Runtime, (u16, u16, u16), Vec<u8>) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\POPUP.NE").unwrap();
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(52)).unwrap();
    let return_to: (u16, u16, u16) = (runtime.cpu.regs.cs, 0x12, runtime.cpu.regs.sp() + 4);
    let state = runtime.win16.as_mut().unwrap();
    let mut bytes = Vec::from(return_to.1.to_le_bytes());
    bytes.extend_from_slice(&return_to.0.to_le_bytes());
    bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    runtime.cpu.regs.set_ax(0xa55a);
    runtime.cpu.regs.set_dx(0x5aa5);
    (runtime, return_to, bytes)
}

fn stack_bytes(runtime: &Runtime, stack: u16) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), stack).unwrap();
    let mut bytes = vec![0; 8];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes
}

#[test]
fn any_popup_dispatch_returns_canonical_bool_without_touching_dx_or_stack_bytes() {
    for result in [false, true] {
        let (mut runtime, return_to, bytes) = prepare();
        let mut host = PopupHost { result, calls: 0, fail: false };
        runtime.win16.as_mut().unwrap().dispatch(
            &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0).unwrap();
        assert_eq!(runtime.cpu.regs.ax(), u16::from(result));
        assert_eq!(runtime.cpu.regs.dx(), 0x5aa5);
        assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), return_to);
        assert_eq!(stack_bytes(&runtime, return_to.2 - 4), bytes);
        assert_eq!(host.calls, 1);
    }
}

#[test]
fn any_popup_dispatch_propagates_host_failure_without_committing_guest_return() {
    let (mut runtime, return_to, bytes) = prepare();
    let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
    let mut host = PopupHost { result: false, calls: 0, fail: true };
    let error = runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut host, 0).unwrap_err();
    assert_eq!(error.kind(), Kind::HostFailure);
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0xa55a, 0x5aa5));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
    assert_eq!(stack_bytes(&runtime, return_to.2 - 4), bytes);
    assert_eq!(host.calls, 1);
}

#[test]
fn any_popup_default_host_is_explicitly_unsupported_in_real_dispatch() {
    let (mut runtime, return_to, bytes) = prepare();
    let before = (runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp());
    let error = runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu, &mut runtime.memory, &mut runtime.dos, &mut NoHost, 0).unwrap_err();
    assert_eq!(error.kind(), Kind::CompatibilityGap);
    assert!(error.to_string().contains("host AnyPopup query is unavailable"));
    assert_eq!((runtime.cpu.regs.ax(), runtime.cpu.regs.dx()), (0xa55a, 0x5aa5));
    assert_eq!((runtime.cpu.regs.cs, runtime.cpu.regs.ip(), runtime.cpu.regs.sp()), before);
    assert_eq!(stack_bytes(&runtime, return_to.2 - 4), bytes);
}
