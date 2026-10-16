//! DOS search exhaustion through protected INT/IRET and KERNEL DOS3Call.

use super::{dispatch_int21, firmware_service_at, resolve_interrupt_target};
use super::super::{
    ImportBinding, interrupt_entry,
    kernel_register_calls::{self, Win16KernelRegisterService},
    test_support::tiny_ne_executable,
};
use crate::{Runtime, RuntimeError, RuntimeHost, Win16CanonicalPath};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosAction, DosDirectoryEntry, DosErrorCode, DosFileAccess, DosFileSharing,
    DosHost, DosHostError, DosHostFile, DosHostSearch, DosSeekOrigin,
};
use guest_core::{GuestMemory, OwnerId, Registers, Selector, io::NoPorts};
use win16_abi::{Access, ExportLookupTarget, lookup_export};

const PATH_OFFSET: u16 = 0x20;
const DTA_OFFSET: u16 = 0x40;
const DTA_SENTINEL: [u8; 43] = [0xa5; 43];
const RETURN_IP: u16 = 0x12;
const HOST_SEARCH: DosHostSearch = DosHostSearch(0x1234);

#[derive(Default)]
struct SearchHost {
    entries: Vec<DosDirectoryEntry>,
    next_entry: usize,
    open: bool,
    open_error: Option<DosErrorCode>,
    directory_activations: usize,
    open_calls: Vec<Vec<u8>>,
    next_calls: Vec<DosHostSearch>,
    close_calls: Vec<DosHostSearch>,
}

impl DosHost for SearchHost {
    fn directory_search_open(&mut self, directory: &[u8]) -> Result<DosHostSearch, DosHostError> {
        assert_eq!(self.directory_activations, 1, "activate the caller's directory first");
        assert!(!self.open);
        self.open_calls.push(directory.to_vec());
        if let Some(code) = self.open_error {
            return Err(DosHostError::new(code));
        }
        self.open = true;
        self.next_entry = 0;
        Ok(HOST_SEARCH)
    }
    fn directory_search_next(&mut self, search: DosHostSearch) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        assert_eq!(search, HOST_SEARCH);
        assert!(self.open, "must not resume a closed search");
        self.next_calls.push(search);
        let entry = self.entries.get(self.next_entry).cloned();
        self.next_entry += 1;
        Ok(entry)
    }
    fn directory_search_close(&mut self, search: DosHostSearch) -> Result<(), DosHostError> {
        assert_eq!(search, HOST_SEARCH);
        assert!(self.open, "must not close a search twice");
        self.close_calls.push(search);
        self.open = false;
        Ok(())
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
    fn guest_code_page(&self) -> text_codec::CodePage { text_codec::CodePage::Cp437 }
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn logical_drive_count(&self) -> u8 { 3 }
}

impl RuntimeHost for SearchHost {
    fn activate_win16_dos_directory(
        &mut self, owner: OwnerId, path: &Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        assert_eq!(owner, OwnerId(1));
        assert_eq!(path, &Win16CanonicalPath { drive: 2, components: vec!["FILES".to_owned()] });
        self.directory_activations += 1;
        Ok(())
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for SearchHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for SearchHost {}
impl crate::RuntimeMidiHost for SearchHost {}
impl crate::RuntimeNetbiosHost for SearchHost {}

#[derive(Clone, Copy, Debug)]
enum Route {
    ProtectedInt21,
    Dos3Call,
}

const ROUTES: [Route; 2] = [Route::ProtectedInt21, Route::Dos3Call];

fn fixture(spec: &[u8]) -> (Runtime, SearchHost) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\SEARCH.NE").unwrap();
    let mut host = SearchHost::default();
    let state = runtime.win16.as_mut().unwrap();
    state.kernel_file_system.seed_owner(OwnerId(1), Win16CanonicalPath {
        drive: 2, components: vec!["FILES".to_owned()],
    }).unwrap();
    let mut path_bytes = spec.to_vec();
    path_bytes.push(0);
    assert!(usize::from(PATH_OFFSET) + path_bytes.len() <= usize::from(DTA_OFFSET));
    let path = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), PATH_OFFSET).unwrap();
    let address = state.selectors.translate(path, Access::Read, path_bytes.len(), &runtime.memory).unwrap();
    assert_ne!(address, guest_core::real_address(runtime.cpu.regs.ds, PATH_OFFSET));
    state.selectors.write(&mut runtime.memory, path, &path_bytes).unwrap();
    let dta = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), DTA_OFFSET).unwrap();
    let address = state.selectors.translate(dta, Access::Write, DTA_SENTINEL.len(), &runtime.memory).unwrap();
    assert_ne!(address, guest_core::real_address(runtime.cpu.regs.ds, DTA_OFFSET));
    state.selectors.write(&mut runtime.memory, dta, &DTA_SENTINEL).unwrap();
    runtime.cpu.regs.set_ax(0x1a00);
    runtime.cpu.regs.set_dx(DTA_OFFSET);
    assert_eq!(dispatch_int21(state, &mut runtime.dos, &mut runtime.cpu.regs,
        &mut runtime.memory, &mut host).unwrap(), DosAction::Continue);
    assert_eq!(host.directory_activations, 0);

    let code = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.cs), 8).unwrap();
    let address = state.selectors.translate(code, Access::Execute, 2, &runtime.memory).unwrap();
    runtime.memory.write(address, &[0xcd, 0x21]).unwrap();
    resolve_interrupt_target(state, 0x21, &mut runtime.memory).unwrap();
    (runtime, host)
}

fn prepare(runtime: &mut Runtime, route: Route, service: u8) -> Registers {
    let ds = runtime.cpu.regs.ds;
    let ss = runtime.cpu.regs.ss;
    let return_cs = runtime.cpu.regs.cs;
    let state = runtime.win16.as_mut().unwrap();
    runtime.cpu.regs = Registers {
        eax: 0xa1a1_0000 | (u32::from(service) << 8), ebx: 0xb2b2_20c2,
        ecx: 0xc3c3_0000, edx: 0xd4d4_0000 | u32::from(PATH_OFFSET),
        esp: 0xe5e5_0080, ebp: 0xf6f6_2468, esi: 0x1717_0010,
        edi: 0x2828_0010, eip: 8, eflags: 0x0ed6,
        cs: return_cs, ds, es: ds, ss, fs: 0x4242, gs: 0x5353,
    };
    let mut expected = runtime.cpu.regs.clone();
    match route {
        Route::ProtectedInt21 => expected.set_ip(10),
        Route::Dos3Call => {
            let stack = state.selectors.pointer_from_raw(Selector(ss), runtime.cpu.regs.sp()).unwrap();
            let mut frame = Vec::from(RETURN_IP.to_le_bytes());
            frame.extend_from_slice(&return_cs.to_le_bytes());
            state.selectors.write(&mut runtime.memory, stack, &frame).unwrap();
            let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(102)).unwrap();
            let slot = state.bindings.len();
            state.bindings.push(ImportBinding::Supported(descriptor));
            runtime.cpu.regs.cs = state.gate_selector.0;
            runtime.cpu.regs.set_ip((slot * 2) as u16);
            expected.set_ip(RETURN_IP);
            expected.set_sp(expected.sp() + 4);
        }
    }
    expected
}

fn call(runtime: &mut Runtime, host: &mut SearchHost, route: Route) -> Result<(), RuntimeError> {
    match route {
        Route::ProtectedInt21 => {
            let state = runtime.win16.as_mut().unwrap();
            let segments = crate::win16_loader::Win16Segments {
                selectors: &state.selectors, memory_len: runtime.memory.len(),
            };
            assert_eq!(runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts,
                &segments).unwrap(), x86_cpu::StepOutcome::Interrupt(0x21));
            state.begin_software_interrupt(0x21, &mut runtime.cpu, &mut runtime.memory)?;
            assert_eq!(firmware_service_at(state, runtime.cpu.regs.cs,
                runtime.cpu.regs.ip(), &runtime.memory)?, Some(0x21));
            assert_eq!(interrupt_entry::call_firmware_service(
                state, &mut runtime.dos, 0x21, &mut runtime.cpu.regs, &mut runtime.memory, host,
            )?, DosAction::Continue);
            let segments = crate::win16_loader::Win16Segments {
                selectors: &state.selectors, memory_len: runtime.memory.len(),
            };
            assert_eq!(runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts,
                &segments).unwrap(), x86_cpu::StepOutcome::Continue);
            assert_eq!(runtime.cpu.control_transfer(), Some(x86_cpu::ControlTransfer::InterruptReturn));
            state.retire_interrupt_return(&runtime.cpu.regs)?;
        }
        Route::Dos3Call => {
            let service = runtime.win16.as_ref().unwrap()
                .kernel_register_service_at(&runtime.cpu.regs)?.unwrap();
            assert_eq!(service, Win16KernelRegisterService::Dos3Call);
            assert_eq!(kernel_register_calls::dispatch(runtime, service, host, 0)?, None);
        }
    }
    Ok(())
}

fn assert_failure(
    runtime: &mut Runtime, host: &mut SearchHost, route: Route, service: u8, error: u16,
) {
    let mut expected = prepare(runtime, route, service);
    expected.set_ax(error);
    expected.set_carry(true);
    call(runtime, host, route).unwrap();
    // Includes the carry returned through IRET, unmentioned registers and
    // high halves, and the DOS3Call far-return stack adjustment.
    assert_eq!(runtime.cpu.regs, expected, "{route:?}, AH={service:02x}");
    let state = runtime.win16.as_ref().unwrap();
    let dta = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), DTA_OFFSET).unwrap();
    let mut bytes = [0; DTA_SENTINEL.len()];
    state.selectors.read(&runtime.memory, dta, &mut bytes).unwrap();
    assert_eq!(bytes, DTA_SENTINEL, "{route:?}, AH={service:02x} must preserve the DTA");
}

fn assert_find_next_has_no_search_io(runtime: &mut Runtime, host: &mut SearchHost, route: Route) {
    let before = (host.directory_activations, host.open_calls.clone(),
        host.next_calls.clone(), host.close_calls.clone());
    assert_failure(runtime, host, route, 0x4f, 18);
    assert_eq!((host.directory_activations, host.open_calls.clone(),
        host.next_calls.clone(), host.close_calls.clone()), before,
        "{route:?}: AH=4Fh must not resume, reopen or close an exhausted search");
    assert!(!host.open);
}

fn entry(name: &[u8], attributes: u8) -> DosDirectoryEntry {
    DosDirectoryEntry {
        short_name: name.to_vec(), attributes,
        write_time: 0, write_date: 0, size: 7,
    }
}

#[test]
fn find_first_routes_report_no_more_files_for_wildcard_mismatch() {
    for route in ROUTES {
        let (mut runtime, mut host) = fixture(br".\*.TXT");
        host.entries.push(entry(b"OTHER.BIN", 0x20));
        assert_failure(&mut runtime, &mut host, route, 0x4e, 18);
        assert_eq!(host.open_calls, [br".\".to_vec()]);
        assert_eq!(host.next_calls, [HOST_SEARCH, HOST_SEARCH]);
        assert_eq!(host.close_calls, [HOST_SEARCH]);
        assert!(!host.open);
        assert_find_next_has_no_search_io(&mut runtime, &mut host, route);
    }
}

#[test]
fn find_first_routes_report_no_more_files_for_attribute_exclusion() {
    for route in ROUTES {
        let (mut runtime, mut host) = fixture(br".\*.TXT");
        host.entries.push(entry(b"MATCH.TXT", 0x02)); // Hidden is excluded by CX=0.
        assert_failure(&mut runtime, &mut host, route, 0x4e, 18);
        assert_eq!(host.open_calls, [br".\".to_vec()]);
        assert_eq!(host.next_calls, [HOST_SEARCH, HOST_SEARCH]);
        assert_eq!(host.close_calls, [HOST_SEARCH]);
        assert!(!host.open);
        assert_find_next_has_no_search_io(&mut runtime, &mut host, route);
    }
}

#[test]
fn find_first_routes_preserve_missing_parent_path_not_found() {
    for route in ROUTES {
        let (mut runtime, mut host) = fixture(br"MISSING\*.TXT");
        host.open_error = Some(DosErrorCode::PathNotFound);
        assert_failure(&mut runtime, &mut host, route, 0x4e, 3);
        assert_eq!(host.open_calls, [br"MISSING\".to_vec()]);
        assert!(host.next_calls.is_empty());
        assert!(host.close_calls.is_empty());
        assert!(!host.open);
        assert_find_next_has_no_search_io(&mut runtime, &mut host, route);
    }
}
