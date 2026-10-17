//! Service-gate coverage for synthesized USER keyboard and mouse input.

use super::super::{ImportBinding, test_support::tiny_ne_executable};
use crate::{
    DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, Win16InjectedKey,
    Win16InjectedMouse,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosDirectoryEntry, DosFileAccess, DosFileSharing, DosHost, DosHostError, DosHostFile,
    DosHostSearch, DosSeekOrigin,
};
use guest_core::Selector;
use win16_abi::{ExportLookupTarget, lookup_export};

#[derive(Default)]
struct RecordingHost {
    keys: Vec<Win16InjectedKey>,
    mice: Vec<Win16InjectedMouse>,
    fail: bool,
}

impl DosHost for RecordingHost {
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

impl RuntimeHost for RecordingHost {
    fn epoch_seconds(&self) -> i64 {
        panic!("unexpected host call")
    }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> {
        panic!("unexpected host call")
    }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> {
        panic!("unexpected host call")
    }
    fn win16_inject_keyboard(&mut self, event: Win16InjectedKey) -> Result<(), RuntimeError> {
        if self.fail {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "keyboard injection rejected",
            ));
        }
        self.keys.push(event);
        Ok(())
    }
    fn win16_inject_mouse(&mut self, event: Win16InjectedMouse) -> Result<(), RuntimeError> {
        if self.fail {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "mouse injection rejected",
            ));
        }
        self.mice.push(event);
        Ok(())
    }
}

impl crate::RuntimeDdeHost for RecordingHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt {
        panic!("unexpected host call")
    }
}
impl crate::RuntimeMciHost for RecordingHost {}
impl crate::RuntimeMidiHost for RecordingHost {}
impl crate::RuntimeNetbiosHost for RecordingHost {}

fn prepare(runtime: &mut Runtime, ordinal: u16) -> (u16, u16, u16) {
    let descriptor = lookup_export(b"USER", ExportLookupTarget::Ordinal(ordinal)).unwrap();
    let return_cs = runtime.cpu.regs.cs;
    let return_ip = 0x12_u16;
    let stack = runtime.cpu.regs.sp();
    let state = runtime.win16.as_mut().unwrap();
    let mut frame = Vec::from(return_ip.to_le_bytes());
    frame.extend_from_slice(&return_cs.to_le_bytes());
    let pointer = state
        .selectors
        .pointer_from_raw(Selector(runtime.cpu.regs.ss), stack)
        .unwrap();
    state
        .selectors
        .write(&mut runtime.memory, pointer, &frame)
        .unwrap();
    let slot = state.bindings.len();
    state.bindings.push(ImportBinding::Supported(descriptor));
    runtime.cpu.regs.cs = state.gate_selector.0;
    runtime.cpu.regs.set_ip((slot * 2) as u16);
    (return_cs, return_ip, stack.wrapping_add(4))
}

fn dispatch(runtime: &mut Runtime, host: &mut RecordingHost) -> Result<Option<u8>, RuntimeError> {
    runtime.win16.as_mut().unwrap().dispatch(
        &mut runtime.cpu,
        &mut runtime.memory,
        &mut runtime.dos,
        host,
        0,
    )
}

#[test]
fn service_gate_records_keyboard_and_mouse_input_without_a_device() {
    let mut host = RecordingHost::default();

    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\KEYBD.NE").unwrap();
    let return_to = prepare(&mut runtime, 289);
    runtime.cpu.regs.eax = 0x0000_8041;
    runtime.cpu.regs.ebx = 0x0000_011e;
    runtime.cpu.regs.ecx = 0x1111_2222;
    runtime.cpu.regs.edx = 0x3333_4444;
    runtime.cpu.regs.esi = 0xaaaa_00ab;
    runtime.cpu.regs.edi = 0xbbbb_00cd;
    runtime.cpu.regs.ebp = 0x5555_6666;
    let mut before = runtime.cpu.regs.clone();
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to,
    );
    before.cs = return_to.0;
    before.set_ip(return_to.1);
    before.set_sp(return_to.2);
    assert_eq!(runtime.cpu.regs, before);
    assert_eq!(
        host.keys,
        vec![Win16InjectedKey {
            virtual_key: 0x41,
            scan: 0x1e,
            flags: 0x0003,
            extra_info: 0x00cd_00ab,
        }]
    );
    assert!(host.mice.is_empty());

    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\MOUSE.NE").unwrap();
    let return_to = prepare(&mut runtime, 299);
    runtime.cpu.regs.eax = 0xffff_8001;
    runtime.cpu.regs.ebx = 0x0000_9c40;
    runtime.cpu.regs.ecx = 0x0000_ffff;
    runtime.cpu.regs.edx = 0x1234_0002;
    runtime.cpu.regs.esi = 0x0000_ffff;
    runtime.cpu.regs.edi = 0x0000_0000;
    runtime.cpu.regs.ebp = 0x0101_0101;
    let mut before = runtime.cpu.regs.clone();
    assert_eq!(dispatch(&mut runtime, &mut host).unwrap(), None);
    assert_eq!(
        (
            runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(),
            runtime.cpu.regs.sp()
        ),
        return_to,
    );
    before.cs = return_to.0;
    before.set_ip(return_to.1);
    before.set_sp(return_to.2);
    assert_eq!(runtime.cpu.regs, before);
    assert_eq!(
        host.mice,
        vec![Win16InjectedMouse {
            flags: 0x8001,
            dx: 0x9c40,
            dy: 0xffff,
            buttons: 2,
            extra_info: 0x0000_ffff,
        }]
    );
}

#[test]
fn rejected_injection_leaves_the_guest_registers_and_records_nothing() {
    let mut host = RecordingHost {
        fail: true,
        ..RecordingHost::default()
    };
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\INPUT.NE").unwrap();
    prepare(&mut runtime, 289);
    runtime.cpu.regs.eax = 0x41;
    runtime.cpu.regs.esi = 0xffff_0000;
    runtime.cpu.regs.edi = 0xffff_ffff;
    let before = runtime.cpu.regs.clone();
    let error = dispatch(&mut runtime, &mut host).unwrap_err();
    assert_eq!(error.kind(), Kind::HostFailure);
    assert_eq!(runtime.cpu.regs, before);
    assert!(host.keys.is_empty());
    assert!(host.mice.is_empty());
}
