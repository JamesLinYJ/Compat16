//! Read-only DOS timestamps through protected INT 21h and KERNEL DOS3Call.

use super::dispatch_int21;
use super::super::{
    ImportBinding,
    kernel_register_calls::{self, Win16KernelRegisterService},
    test_support::tiny_ne_executable,
};
use crate::{Runtime, RuntimeError, RuntimeHost, Win16CanonicalPath, Win16GuestPath};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosAction, DosDirectoryEntry, DosErrorCode, DosFileAccess, DosFileSharing,
    DosFileStatus, DosHost, DosHostError, DosHostFile, DosHostSearch,
    DosIoctlObjectInfo, DosSeekOrigin,
};
use guest_core::{OwnerId, Registers, Selector};
use win16_abi::{Access, ExportLookupTarget, Win16KernelFileSystemRequest, lookup_export};

const HOST_FILE: DosHostFile = DosHostFile(0x1234);
const WRITE_TIME: u16 = (14 << 11) | (53 << 5) | (26 / 2);
const WRITE_DATE: u16 = ((2026 - 1980) << 9) | (10 << 5) | 10;
const RETURN_IP: u16 = 0x12;

#[derive(Default)]
struct TimestampHost {
    open: bool,
    directory_activations: usize,
    status_calls: Vec<DosHostFile>,
    next_status_error: Option<DosErrorCode>,
}

impl DosHost for TimestampHost {
    fn file_ioctl_info(&self, file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        assert_eq!(file, HOST_FILE);
        assert!(self.open);
        Ok(DosIoctlObjectInfo::File { drive: 2, written: false })
    }
    fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        assert_eq!(file, HOST_FILE);
        assert!(self.open);
        self.status_calls.push(file);
        // Fail the service query once, then allow the ordinary SFT refresh.
        if let Some(code) = self.next_status_error.take() {
            return Err(DosHostError::new(code));
        }
        Ok(DosFileStatus {
            short_name: *b"STAMP   DAT", size: 0x1020, position: 7,
            attributes: 0x21, write_time: WRITE_TIME, write_date: WRITE_DATE,
        })
    }
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, path: &[u8], access: DosFileAccess) -> Result<DosHostFile, DosHostError> {
        assert_eq!(path, b"STAMP.DAT");
        assert_eq!(access, DosFileAccess::ReadOnly);
        assert!(!self.open);
        assert_eq!(self.directory_activations, 1);
        self.open = true;
        Ok(HOST_FILE)
    }
    fn file_open_with_sharing(&mut self, path: &[u8], access: DosFileAccess, sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> {
        assert_eq!(sharing, DosFileSharing::Compatibility);
        self.file_open(path, access)
    }
    fn file_duplicate(&mut self, _file: DosHostFile) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        assert_eq!(file, HOST_FILE);
        assert!(self.open);
        self.open = false;
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

impl RuntimeHost for TimestampHost {
    fn activate_win16_dos_directory(
        &mut self, owner: OwnerId, path: &Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        assert_eq!(owner, OwnerId(1));
        assert_eq!(path, &Win16CanonicalPath { drive: 2, components: vec!["FILES".to_owned()] });
        self.directory_activations += 1;
        Ok(())
    }
    fn normalize_win16_dos_path(
        &mut self, _owner: OwnerId, _path: &Win16GuestPath,
    ) -> Result<Option<Win16CanonicalPath>, RuntimeError> {
        panic!("timestamp reads must not resolve paths or capture FileCDR notices")
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for TimestampHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for TimestampHost {}
impl crate::RuntimeMidiHost for TimestampHost {}
impl crate::RuntimeNetbiosHost for TimestampHost {}

#[derive(Clone, Copy, Debug)]
enum Route {
    ProtectedInt21,
    Dos3Call,
}

const ROUTES: [Route; 2] = [Route::ProtectedInt21, Route::Dos3Call];

fn fixture() -> (Runtime, TimestampHost, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\STAMP.NE").unwrap();
    let mut host = TimestampHost::default();
    let state = runtime.win16.as_mut().unwrap();
    state.kernel_file_system.seed_owner(OwnerId(1), Win16CanonicalPath {
        drive: 2, components: vec!["FILES".to_owned()],
    }).unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x20).unwrap();
    let address = state.selectors.translate(pointer, Access::Read, 10, &runtime.memory).unwrap();
    assert_ne!(address, guest_core::real_address(runtime.cpu.regs.ds, 0x20));
    state.selectors.write(&mut runtime.memory, pointer, b"STAMP.DAT\0").unwrap();
    runtime.cpu.regs.set_ax(0x3d00); // The handle is opened read-only through the caller's selector.
    runtime.cpu.regs.set_dx(0x20);
    assert_eq!(dispatch_int21(state, &mut runtime.dos, &mut runtime.cpu.regs, &mut runtime.memory, &mut host).unwrap(), DosAction::Continue);
    assert!(!runtime.cpu.regs.carry());
    let handle = runtime.cpu.regs.ax();
    assert!(host.open);
    assert_eq!(host.status_calls, [HOST_FILE]);

    // Install a real executable callback so the absence of a notice is tested
    // with FileCDR enabled, rather than relying on an empty registration.
    let procedure = (u32::from(runtime.cpu.regs.cs) << 16) | 0x30;
    assert_eq!(state.execute_kernel_file_system(
        Win16KernelFileSystemRequest::FileCdr { procedure }, &mut runtime.memory, &mut host,
    ).unwrap(), 1);
    assert_eq!(state.kernel_file_system.file_cdr_query(), procedure);
    host.status_calls.clear();
    host.directory_activations = 0;
    (runtime, host, handle)
}

fn prepare(runtime: &mut Runtime, route: Route, handle: u16, subfunction: u8) -> Registers {
    let ds = runtime.cpu.regs.ds;
    let ss = runtime.cpu.regs.ss;
    let return_cs = runtime.cpu.regs.cs;
    runtime.cpu.regs = Registers {
        eax: 0xa1a1_5700 | u32::from(subfunction), ebx: 0xb2b2_0000 | u32::from(handle),
        ecx: 0xc3c3_4567, edx: 0xd4d4_0020,
        esp: 0xe5e5_0080, ebp: 0xf6f6_2468, esi: 0x1717_1357, edi: 0x2828_0010,
        eip: 0x3939_0008, eflags: 0x0024_0ed7,
        cs: return_cs, ds, es: ds, ss, fs: 0x4242, gs: 0x5353,
    };
    if let Route::Dos3Call = route {
        let state = runtime.win16.as_mut().unwrap();
        let stack = state.selectors.pointer_from_raw(Selector(ss), runtime.cpu.regs.sp()).unwrap();
        let mut frame = Vec::from(RETURN_IP.to_le_bytes());
        frame.extend_from_slice(&return_cs.to_le_bytes());
        state.selectors.write(&mut runtime.memory, stack, &frame).unwrap();
        let descriptor = lookup_export(b"KERNEL", ExportLookupTarget::Ordinal(102)).unwrap();
        let slot = state.bindings.len();
        state.bindings.push(ImportBinding::Supported(descriptor));
        runtime.cpu.regs.cs = state.gate_selector.0;
        runtime.cpu.regs.set_ip((slot * 2) as u16);
    }
    let mut expected = runtime.cpu.regs.clone();
    if let Route::Dos3Call = route {
        expected.cs = return_cs;
        expected.set_ip(RETURN_IP);
        expected.set_sp(expected.sp() + 4);
    }
    expected
}

fn use_invalid_data_selectors(runtime: &mut Runtime, expected: &mut Registers, selector: u16) {
    assert!(runtime.win16.as_ref().unwrap().selectors.pointer_from_raw(Selector(selector), 0).is_err());
    runtime.cpu.regs.ds = selector;
    runtime.cpu.regs.es = selector;
    expected.ds = selector;
    expected.es = selector;
}

fn call(runtime: &mut Runtime, host: &mut TimestampHost, route: Route, expected: Registers, status_calls: usize) {
    match route {
        Route::ProtectedInt21 => {
            assert_eq!(dispatch_int21(
                runtime.win16.as_mut().unwrap(), &mut runtime.dos,
                &mut runtime.cpu.regs, &mut runtime.memory, host,
            ).unwrap(), DosAction::Continue);
        }
        Route::Dos3Call => {
            let service = runtime.win16.as_ref().unwrap()
                .kernel_register_service_at(&runtime.cpu.regs).unwrap().unwrap();
            assert_eq!(service, Win16KernelRegisterService::Dos3Call);
            assert_eq!(kernel_register_calls::dispatch(runtime, service, host, 0).unwrap(), None);
        }
    }
    // Equality includes every untouched register, all high halves, non-CF
    // flags, and DOS3Call's checked CS:IP/SP far-return adjustment.
    assert_eq!(runtime.cpu.regs, expected, "{route:?}");
    assert_eq!(host.status_calls, vec![HOST_FILE; status_calls], "{route:?}");
    assert_eq!(host.directory_activations, 0, "{route:?}");
    let state = runtime.win16.as_mut().unwrap();
    assert!(!state.kernel_file_system.has_active_callback(), "{route:?}");
    assert!(!state.begin_pending_file_cdr_callback(
        &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, host,
    ).unwrap(), "{route:?}");
    assert_eq!(runtime.cpu.regs, expected, "{route:?}");
}

#[test]
fn timestamp_read_routes_preserve_registers_with_null_or_unmapped_data_selectors() {
    for route in ROUTES {
        for selector in [0, 0xfff8] {
            let (mut runtime, mut host, handle) = fixture();
            let mut expected = prepare(&mut runtime, route, handle, 0);
            use_invalid_data_selectors(&mut runtime, &mut expected, selector);
            expected.set_cx(WRITE_TIME);
            expected.set_dx(WRITE_DATE);
            expected.set_carry(false);
            // One service query and one refresh of the open file's SFT entry.
            call(&mut runtime, &mut host, route, expected, 2);
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
    }
}

#[test]
fn timestamp_read_routes_do_not_capture_file_cdr_paths() {
    for route in ROUTES {
        let (mut runtime, mut host, handle) = fixture();
        let mut expected = prepare(&mut runtime, route, handle, 0);
        // DS:DX still names a valid path. Any accidental FileCDR capture would
        // reach normalize_win16_dos_path and fail rather than be hidden by NULL.
        expected.set_cx(WRITE_TIME);
        expected.set_dx(WRITE_DATE);
        expected.set_carry(false);
        call(&mut runtime, &mut host, route, expected, 2);
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
    }
}

#[test]
fn timestamp_read_routes_return_host_error_without_overwriting_time_or_date() {
    for route in ROUTES {
        let (mut runtime, mut host, handle) = fixture();
        let mut expected = prepare(&mut runtime, route, handle, 0);
        use_invalid_data_selectors(&mut runtime, &mut expected, 0);
        runtime.cpu.regs.set_carry(false);
        host.next_status_error = Some(DosErrorCode::AccessDenied);
        expected.set_ax(DosErrorCode::AccessDenied as u16);
        expected.set_carry(true);
        call(&mut runtime, &mut host, route, expected, 2);
        assert!(host.next_status_error.is_none());
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
    }
}

#[test]
fn timestamp_read_routes_reject_missing_and_standard_handles_without_querying_them() {
    for route in ROUTES {
        for (handle, error) in [(0xffff, DosErrorCode::InvalidHandle), (0, DosErrorCode::InvalidFunction)] {
            let (mut runtime, mut host, _) = fixture();
            let mut expected = prepare(&mut runtime, route, handle, 0);
            use_invalid_data_selectors(&mut runtime, &mut expected, 0);
            runtime.cpu.regs.set_carry(false);
            expected.set_ax(error as u16);
            expected.set_carry(true);
            // The unrelated open file still receives its ordinary SFT refresh.
            call(&mut runtime, &mut host, route, expected, 1);
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
    }
}

#[test]
fn timestamp_read_routes_reject_closed_handles_without_host_queries() {
    for route in ROUTES {
        let (mut runtime, mut host, handle) = fixture();
        runtime.cpu.regs.set_ax(0x3e00);
        runtime.cpu.regs.set_bx(handle);
        assert_eq!(dispatch_int21(
            runtime.win16.as_mut().unwrap(), &mut runtime.dos,
            &mut runtime.cpu.regs, &mut runtime.memory, &mut host,
        ).unwrap(), DosAction::Continue);
        assert!(!runtime.cpu.regs.carry());
        assert!(!host.open);
        assert!(host.status_calls.is_empty());
        let mut expected = prepare(&mut runtime, route, handle, 0);
        use_invalid_data_selectors(&mut runtime, &mut expected, 0);
        runtime.cpu.regs.set_carry(false);
        expected.set_ax(DosErrorCode::InvalidHandle as u16);
        expected.set_carry(true);
        call(&mut runtime, &mut host, route, expected, 0);
    }
}

#[test]
fn timestamp_read_routes_reject_unsupported_subfunctions_before_querying_the_handle() {
    for route in ROUTES {
        for subfunction in [1, 2, 0xff] {
            let (mut runtime, mut host, handle) = fixture();
            let mut expected = prepare(&mut runtime, route, handle, subfunction);
            use_invalid_data_selectors(&mut runtime, &mut expected, 0);
            runtime.cpu.regs.set_carry(false);
            expected.set_ax(DosErrorCode::InvalidFunction as u16);
            expected.set_carry(true);
            // Refresh-only, including AL=01h: no setter or timestamp query.
            call(&mut runtime, &mut host, route, expected, 1);
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
    }
}
