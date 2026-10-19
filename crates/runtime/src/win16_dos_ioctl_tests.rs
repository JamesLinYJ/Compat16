//! Owned KERNEL file information through protected INT 21h and KERNEL DOS3Call.

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
    DosIoctlObjectInfo, DosIoctlStream, DosSeekOrigin,
};
use guest_core::{GuestMemory, OwnerId, Registers, Selector, real_address};
use win16_abi::{Access, ExportLookupTarget, Win16KernelFileSystemRequest, lookup_export};

const HOST_FILE: DosHostFile = DosHostFile(0x1234);
const WRITE_TIME: u16 = (14 << 11) | (53 << 5) | (26 / 2);
const WRITE_DATE: u16 = ((2026 - 1980) << 9) | (10 << 5) | 10;
const RETURN_IP: u16 = 0x12;

#[derive(Default)]
struct IoctlHost {
    tokens: Vec<DosHostFile>,
    directory_activations: usize,
    status_calls: Vec<DosHostFile>,
    commit_calls: Vec<DosHostFile>,
    next_commit_error: Option<DosErrorCode>,
    standard_info: Option<DosIoctlObjectInfo>,
    win16_info: Option<Result<DosIoctlObjectInfo, DosHostError>>,
    win16_queries: Vec<crate::Win16HostFile>,
}

impl DosHost for IoctlHost {
    fn file_ioctl_info(&self, file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        assert!(self.tokens.contains(&file));
        Ok(DosIoctlObjectInfo::File { drive: 2, written: false })
    }
    fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        assert!(self.tokens.contains(&file));
        self.status_calls.push(file);
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
        assert_eq!(access, DosFileAccess::ReadWrite);
        assert!(self.tokens.is_empty());
        assert_eq!(self.directory_activations, 1);
        self.tokens.push(HOST_FILE);
        Ok(HOST_FILE)
    }
    fn file_open_with_sharing(&mut self, path: &[u8], access: DosFileAccess, sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> {
        assert_eq!(sharing, DosFileSharing::Compatibility);
        self.file_open(path, access)
    }
    fn file_duplicate(&mut self, file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        assert!(self.tokens.contains(&file));
        let duplicate = DosHostFile(self.tokens.iter().map(|token| token.0).max().unwrap() + 1);
        self.tokens.push(duplicate);
        Ok(duplicate)
    }
    fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        assert!(self.tokens.contains(&file));
        self.tokens.retain(|token| *token != file);
        Ok(())
    }
    fn file_commit(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        assert!(self.tokens.contains(&file));
        self.commit_calls.push(file);
        match self.next_commit_error.take() {
            Some(code) => Err(DosHostError::new(code)),
            None => Ok(()),
        }
    }
    fn standard_ioctl_info(&self, _stream: DosIoctlStream) -> Result<DosIoctlObjectInfo, DosHostError> {
        self.standard_info.ok_or_else(|| DosHostError::new(DosErrorCode::InvalidFunction))
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

impl RuntimeHost for IoctlHost {
    fn win16_file_ioctl_info(&mut self, file: crate::Win16HostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        self.win16_queries.push(file);
        match &self.win16_info {
            Some(Ok(info)) => Ok(*info),
            Some(Err(error)) => Err(DosHostError::new(error.code)),
            None => Err(DosHostError::new(DosErrorCode::InvalidFunction)),
        }
    }
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
        panic!("commit must not resolve paths or capture FileCDR notices")
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for IoctlHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for IoctlHost {}
impl crate::RuntimeMidiHost for IoctlHost {}
impl crate::RuntimeNetbiosHost for IoctlHost {}

#[derive(Clone, Copy, Debug)]
enum Route {
    ProtectedInt21,
    Dos3Call,
}

const ROUTES: [Route; 2] = [Route::ProtectedInt21, Route::Dos3Call];

fn fixture() -> (Runtime, IoctlHost, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\STAMP.NE").unwrap();
    let mut host = IoctlHost::default();
    let state = runtime.win16.as_mut().unwrap();
    state.kernel_file_system.seed_owner(OwnerId(1), Win16CanonicalPath {
        drive: 2, components: vec!["FILES".to_owned()],
    }).unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x20).unwrap();
    let address = state.selectors.translate(pointer, Access::Read, 10, &runtime.memory).unwrap();
    assert_ne!(address, guest_core::real_address(runtime.cpu.regs.ds, 0x20));
    state.selectors.write(&mut runtime.memory, pointer, b"STAMP.DAT\0").unwrap();
    runtime.cpu.regs.set_ax(0x3d02); // Open the DOS handle through the caller's selector.
    runtime.cpu.regs.set_dx(0x20);
    assert_eq!(dispatch_int21(state, &mut runtime.dos, &mut runtime.cpu.regs, &mut runtime.memory, &mut host).unwrap(), DosAction::Continue);
    assert!(!runtime.cpu.regs.carry());
    let handle = runtime.cpu.regs.ax();
    assert_eq!(host.tokens, [HOST_FILE]);
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

fn prepare(runtime: &mut Runtime, route: Route, handle: u16, al: u8) -> Registers {
    let ds = runtime.cpu.regs.ds;
    let ss = runtime.cpu.regs.ss;
    let return_cs = runtime.cpu.regs.cs;
    runtime.cpu.regs = Registers {
        eax: 0xa1a1_4400 | u32::from(al), ebx: 0xb2b2_0000 | u32::from(handle),
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

fn call(runtime: &mut Runtime, host: &mut IoctlHost, route: Route, expected: Registers, committed: &[DosHostFile]) {
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
    assert_eq!(host.commit_calls, committed, "{route:?}");
    assert_eq!(host.directory_activations, 0, "{route:?}");
    let state = runtime.win16.as_mut().unwrap();
    assert!(!state.kernel_file_system.has_active_callback(), "{route:?}");
    assert!(!state.begin_pending_file_cdr_callback(
        &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, host,
    ).unwrap(), "{route:?}");
    assert_eq!(runtime.cpu.regs, expected, "{route:?}");
}

const KERNEL_FILE: crate::Win16HostFile = crate::Win16HostFile(0x5678);

#[test]
fn file_ioctl_routes_query_exact_kernel_identity_and_preserve_scalar_registers() {
    for route in ROUTES {
        for (drive, written) in [(0, false), (2, true), (25, false)] {
            let (mut runtime, mut host, handle) = fixture();
            // Deliberately collide with a live DOS JFT entry.
            runtime.win16.as_mut().unwrap().files.insert(handle, KERNEL_FILE);
            host.win16_info = Some(Ok(DosIoctlObjectInfo::File { drive, written }));
            let mut expected = prepare(&mut runtime, route, handle, 0);
            use_invalid_data_selectors(&mut runtime, &mut expected, 0);
            expected.set_dx(u16::from(drive) | (u16::from(!written) << 6));
            expected.set_carry(false);
            call(&mut runtime, &mut host, route, expected, &[]);
            assert_eq!(host.win16_queries, [KERNEL_FILE]);
            assert_eq!(host.tokens, [HOST_FILE]);
            runtime.win16.as_mut().unwrap().files.clear();
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
    }
}

#[test]
fn file_ioctl_routes_keep_dos_fallback_and_invalid_handle_errors() {
    for route in ROUTES {
        for unknown in [false, true] {
            let (mut runtime, mut host, handle) = fixture();
            let mut expected = prepare(&mut runtime, route, if unknown { 0x7654 } else { handle }, 0);
            if unknown {
                expected.set_ax(DosErrorCode::InvalidHandle as u16);
            } else { expected.set_dx(0x42); }
            expected.set_carry(unknown);
            call(&mut runtime, &mut host, route, expected, &[]);
            assert!(host.win16_queries.is_empty());
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
    }
}

#[test]
fn file_ioctl_routes_propagate_native_errors_without_selecting_dos_collision() {
    for route in ROUTES {
        for code in [DosErrorCode::InvalidHandle, DosErrorCode::AccessDenied, DosErrorCode::InvalidFunction] {
            let (mut runtime, mut host, handle) = fixture();
            runtime.win16.as_mut().unwrap().files.insert(handle, KERNEL_FILE);
            host.win16_info = Some(Err(DosHostError::new(code)));
            let mut expected = prepare(&mut runtime, route, handle, 0);
            expected.set_ax(code as u16);
            expected.set_carry(true);
            call(&mut runtime, &mut host, route, expected, &[]);
            assert_eq!(host.win16_queries, [KERNEL_FILE]);
            runtime.win16.as_mut().unwrap().files.clear();
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
    }
}

#[test]
fn file_ioctl_routes_reject_unsupported_subfunctions_and_owned_spool_aliases() {
    for route in ROUTES {
        for alias in 0..3 {
            for al in [0, 1, 2, 6, 0xff] {
                if alias == 0 && al == 0 { continue; }
                let (mut runtime, mut host, handle) = fixture();
                let state = runtime.win16.as_mut().unwrap();
                if alias == 0 { state.files.insert(handle, KERNEL_FILE); }
                else {
                    state.network_print_jobs.entry(OwnerId(alias)).or_default().insert_open_job(
                        handle, crate::Win16HostSpoolJob::new(0x6789), b"QUEUE".to_vec(), None,
                    ).unwrap();
                }
                let mut expected = prepare(&mut runtime, route, handle, al);
                expected.set_ax(DosErrorCode::InvalidFunction as u16);
                expected.set_carry(true);
                call(&mut runtime, &mut host, route, expected, &[]);
                assert!(host.win16_queries.is_empty());
                let state = runtime.win16.as_mut().unwrap();
                state.files.clear(); state.network_print_jobs.clear();
                runtime.dos.close_all_handles_checked(&mut host).unwrap();
            }
        }
    }
}

#[test]
fn file_ioctl_routes_preflight_corrupt_metadata_before_native_query() {
    for route in ROUTES {
        let (mut runtime, mut host, handle) = fixture();
        runtime.win16.as_mut().unwrap().files.insert(handle, KERNEL_FILE);
        let _ = prepare(&mut runtime, route, handle, 0);
        let before = runtime.cpu.regs.clone();
        runtime.memory.write(real_address(runtime.dos.psp_segment(), 0x34), &[0xff; 4]).unwrap();
        let result = match route {
            Route::ProtectedInt21 => dispatch_int21(runtime.win16.as_mut().unwrap(), &mut runtime.dos,
                &mut runtime.cpu.regs, &mut runtime.memory, &mut host).map(|_| ()),
            Route::Dos3Call => kernel_register_calls::dispatch(&mut runtime,
                Win16KernelRegisterService::Dos3Call, &mut host, 0).map(|_| ()),
        };
        assert!(result.is_err());
        assert_eq!(runtime.cpu.regs, before);
        assert!(host.win16_queries.is_empty());
    }
}

#[test]
fn file_ioctl_routes_reject_invalid_host_drive_without_publishing_success() {
    for route in ROUTES {
        let (mut runtime, mut host, handle) = fixture();
        runtime.win16.as_mut().unwrap().files.insert(handle, KERNEL_FILE);
        host.win16_info = Some(Ok(DosIoctlObjectInfo::File { drive: 26, written: false }));
        let _ = prepare(&mut runtime, route, handle, 0);
        let before = runtime.cpu.regs.clone();
        let result = match route {
            Route::ProtectedInt21 => dispatch_int21(runtime.win16.as_mut().unwrap(), &mut runtime.dos,
                &mut runtime.cpu.regs, &mut runtime.memory, &mut host).map(|_| ()),
            Route::Dos3Call => kernel_register_calls::dispatch(&mut runtime,
                Win16KernelRegisterService::Dos3Call, &mut host, 0).map(|_| ()),
        };
        assert!(result.is_err());
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(host.win16_queries, [KERNEL_FILE]);
    }
}
