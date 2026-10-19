//! WNet HFILE ownership through protected INT/IRET and KERNEL DOS3Call.

use super::{dispatch_int21, firmware_service_at, resolve_interrupt_target};
use super::super::{
    ImportBinding, interrupt_entry,
    kernel_register_calls::{self, Win16KernelRegisterService},
    test_support::tiny_ne_executable,
};
use crate::{
    Runtime, RuntimeError, RuntimeHost, Win16CanonicalPath, Win16GuestPath,
    Win16HostSpoolJob, Win16HostSpoolOperation, Win16HostSpoolResult, Win16IoEvent,
};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosAction, DosDirectoryEntry, DosErrorCode, DosFileAccess, DosFileSharing,
    DosFileStatus, DosHost, DosHostError, DosHostFile, DosHostSearch,
    DosIoctlObjectInfo, DosSeekOrigin,
};
use guest_core::{GuestMemory, OwnerId, Registers, Selector, io::NoPorts, real_address};
use win16_abi::{
    Access, ExportLookupTarget, Win16KernelFileSystemRequest, Win16UserNetworkRequest,
    lookup_export, network_print_abi::WN_SUCCESS,
};

const HOST_FILE: DosHostFile = DosHostFile(0x1234);
const HOST_JOB: Win16HostSpoolJob = Win16HostSpoolJob::new(0x6789);
const RETURN_IP: u16 = 0x12;
const DATA_OFFSET: u16 = 0x40;
const DATA: &[u8] = &[0x41, 0x00, 0x82, 0xff];

#[derive(Default)]
struct SpoolHost {
    tokens: Vec<DosHostFile>,
    writes: Vec<(DosHostFile, Vec<u8>)>,
    closes: Vec<DosHostFile>,
    truncations: Vec<(DosHostFile, u32)>,
    spool_calls: Vec<Win16HostSpoolOperation>,
    io_notices: Vec<(&'static str, u16, Option<u32>)>,
    dos_notices: Vec<(Registers, Registers)>,
    directory_activations: usize,
    status_calls: usize,
    next_spool_error: Option<u32>,
    next_write_count: Option<u32>,
    next_status_error: Option<DosErrorCode>,
}

impl DosHost for SpoolHost {
    fn file_ioctl_info(&self, file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        assert!(self.tokens.contains(&file));
        Ok(DosIoctlObjectInfo::File { drive: 2, written: false })
    }
    fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        assert!(self.tokens.contains(&file));
        self.status_calls += 1;
        if let Some(code) = self.next_status_error.take() {
            return Err(DosHostError::new(code));
        }
        Ok(DosFileStatus {
            short_name: *b"OTHER   DAT", size: 32, position: 7,
            attributes: 0x20, write_time: 0, write_date: 0,
        })
    }
    fn file_open(&mut self, path: &[u8], access: DosFileAccess) -> Result<DosHostFile, DosHostError> {
        assert_eq!(path, b"OTHER.DAT");
        assert_eq!(access, DosFileAccess::ReadWrite);
        assert!(self.tokens.is_empty());
        self.tokens.push(HOST_FILE);
        Ok(HOST_FILE)
    }
    fn file_open_with_sharing(&mut self, path: &[u8], access: DosFileAccess, sharing: DosFileSharing) -> Result<DosHostFile, DosHostError> {
        assert_eq!(sharing, DosFileSharing::Compatibility);
        self.file_open(path, access)
    }
    fn file_duplicate(&mut self, file: DosHostFile) -> Result<DosHostFile, DosHostError> {
        assert!(self.tokens.contains(&file));
        let duplicate = DosHostFile(file.0 + 1);
        assert!(!self.tokens.contains(&duplicate));
        self.tokens.push(duplicate);
        Ok(duplicate)
    }
    fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        assert!(self.tokens.contains(&file));
        self.closes.push(file);
        self.tokens.retain(|token| *token != file);
        Ok(())
    }
    fn file_write(&mut self, file: DosHostFile, input: &[u8]) -> Result<usize, DosHostError> {
        assert!(self.tokens.contains(&file));
        self.writes.push((file, input.to_vec()));
        Ok(input.len())
    }
    fn file_seek(&mut self, file: DosHostFile, offset: i32, origin: DosSeekOrigin) -> Result<u32, DosHostError> {
        assert!(self.tokens.contains(&file));
        assert_eq!((offset, origin), (0, DosSeekOrigin::Current));
        Ok(7)
    }
    fn file_set_len(&mut self, file: DosHostFile, length: u32) -> Result<(), DosHostError> {
        assert!(self.tokens.contains(&file));
        self.truncations.push((file, length));
        Ok(())
    }
    fn guest_code_page(&self) -> text_codec::CodePage { text_codec::CodePage::Cp437 }
    fn logical_drive_count(&self) -> u8 { 3 }
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_read(&mut self, _file: DosHostFile, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
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
    fn current_drive(&self) -> u8 { panic!("unexpected host call") }
    fn select_drive(&mut self, _drive: u8) -> Result<(), DosHostError> { panic!("unexpected host call") }
}

impl RuntimeHost for SpoolHost {
    fn activate_win16_dos_directory(&mut self, _owner: OwnerId, _path: &Win16CanonicalPath) -> Result<(), RuntimeError> {
        self.directory_activations += 1;
        Ok(())
    }
    fn normalize_win16_dos_path(&mut self, _owner: OwnerId, _path: &Win16GuestPath) -> Result<Option<Win16CanonicalPath>, RuntimeError> {
        panic!("close/write must not resolve paths or capture FileCDR notices")
    }
    fn win16_spool(&mut self, operation: Win16HostSpoolOperation) -> Result<Win16HostSpoolResult, RuntimeError> {
        self.spool_calls.push(operation.clone());
        Ok(match operation {
            Win16HostSpoolOperation::NetworkOpenJob { owner, queue, document_name, copies } => {
                assert_eq!(owner, OwnerId(1));
                assert_eq!(queue, b"QUEUE");
                assert_eq!(document_name, Some(b"Document".to_vec()));
                assert_eq!(copies, 1);
                Win16HostSpoolResult::NetworkOpenJob {
                    job: Some(HOST_JOB), queue_name: Some(b"QUEUE".to_vec()),
                    copies_applied: true, native_error: None, copies_error: None,
                    copies_diagnostic: None,
                }
            }
            Win16HostSpoolOperation::Write { job, bytes } => {
                assert_eq!(job, HOST_JOB);
                let native_error = self.next_spool_error.take();
                Win16HostSpoolResult::Write {
                    bytes_written: self.next_write_count.take()
                        .unwrap_or(if native_error.is_some() { 0 } else { bytes.len() as u32 }),
                    native_error,
                }
            }
            Win16HostSpoolOperation::ReleaseNetworkJob { job } => {
                assert_eq!(job, HOST_JOB);
                let native_error = self.next_spool_error.take();
                Win16HostSpoolResult::Status { succeeded: native_error.is_none(), native_error }
            }
            _ => panic!("unexpected spool operation"),
        })
    }
    fn observe_win16_io(&mut self, event: &Win16IoEvent<'_>) {
        match event {
            Win16IoEvent::Close { file, result } => self.io_notices.push(("close", *file, *result)),
            Win16IoEvent::Transfer { operation, file, result, .. } => self.io_notices.push((*operation, *file, *result)),
            _ => {}
        }
    }
    fn observe_dos_service(&mut self, _instruction_count: u64, before: &Registers, after: &Registers) {
        self.dos_notices.push((before.clone(), after.clone()));
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for SpoolHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for SpoolHost {}
impl crate::RuntimeMidiHost for SpoolHost {}
impl crate::RuntimeNetbiosHost for SpoolHost {}

#[derive(Clone, Copy, Debug)]
enum Route { ProtectedInt21, Dos3Call }
const ROUTES: [Route; 2] = [Route::ProtectedInt21, Route::Dos3Call];

fn fixture() -> (Runtime, SpoolHost, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\SPOOL.NE").unwrap();
    let mut host = SpoolHost::default();
    let state = runtime.win16.as_mut().unwrap();
    state.tasks.create(OwnerId(2), Some(OwnerId(1))).unwrap();
    state.kernel_file_system.seed_owner(OwnerId(1), Win16CanonicalPath {
        drive: 2, components: vec!["FILES".to_owned()],
    }).unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x20).unwrap();
    state.selectors.write(&mut runtime.memory, pointer, b"OTHER.DAT\0").unwrap();
    runtime.cpu.regs.set_ax(0x3d02);
    runtime.cpu.regs.set_dx(0x20);
    assert_eq!(dispatch_int21(state, &mut runtime.dos, &mut runtime.cpu.regs, &mut runtime.memory, &mut host).unwrap(), DosAction::Continue);
    assert!(!runtime.cpu.regs.carry());
    let handle = runtime.cpu.regs.ax();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), DATA_OFFSET).unwrap();
    let address = state.selectors.translate(pointer, Access::Read, DATA.len(), &runtime.memory).unwrap();
    assert_ne!(address, real_address(runtime.cpu.regs.ds, DATA_OFFSET));
    state.selectors.write(&mut runtime.memory, pointer, DATA).unwrap();
    let mut wrong_bytes = [0; DATA.len()];
    runtime.memory.read(real_address(runtime.cpu.regs.ds, DATA_OFFSET), &mut wrong_bytes).unwrap();
    assert_ne!(wrong_bytes, DATA);
    let code = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.cs), 8).unwrap();
    let code = state.selectors.translate(code, Access::Execute, 2, &runtime.memory).unwrap();
    runtime.memory.write(code, &[0xcd, 0x21]).unwrap();
    resolve_interrupt_target(state, 0x21, &mut runtime.memory).unwrap();
    let procedure = (u32::from(runtime.cpu.regs.cs) << 16) | 0x30;
    assert_eq!(state.execute_kernel_file_system(
        Win16KernelFileSystemRequest::FileCdr { procedure }, &mut runtime.memory, &mut host,
    ).unwrap(), 1);
    host.directory_activations = 0;
    host.status_calls = 0;
    (runtime, host, handle)
}

fn open_spool(runtime: &mut Runtime, host: &mut SpoolHost) -> u16 {
    let output = (u32::from(runtime.cpu.regs.ds) << 16) | 0x60;
    let state = runtime.win16.as_mut().unwrap();
    assert_eq!(state.dispatch_network_print(Win16UserNetworkRequest::OpenJob {
        queue: b"QUEUE".to_vec(), job_name: Some(b"Document".to_vec()),
        copies: 1, hfile_output: output,
    }, &mut runtime.memory, host).unwrap(), Some(WN_SUCCESS));
    let pointer = state.selectors.pointer_from_far(output).unwrap();
    let mut bytes = [0; 2];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    let hfile = u16::from_le_bytes(bytes);
    assert_eq!(hfile, 255);
    host.spool_calls.clear();
    hfile
}

fn install_spool_alias(runtime: &mut Runtime, owner: OwnerId, hfile: u16, reserved: bool) {
    let jobs = runtime.win16.as_mut().unwrap().network_print_jobs.entry(owner).or_default();
    if reserved {
        assert!(jobs.reserve_hfile(hfile).unwrap());
    } else {
        jobs.insert_open_job(hfile, HOST_JOB, b"QUEUE".to_vec(), None).unwrap();
    }
}

fn prepare(runtime: &mut Runtime, route: Route, service: u8, handle: u16, count: u16) -> Registers {
    let ds = runtime.cpu.regs.ds;
    let ss = runtime.cpu.regs.ss;
    let return_cs = runtime.cpu.regs.cs;
    let state = runtime.win16.as_mut().unwrap();
    runtime.cpu.regs = Registers {
        eax: 0xa1a1_005a | (u32::from(service) << 8), ebx: 0xb2b2_0000 | u32::from(handle),
        ecx: 0xc3c3_0000 | u32::from(count), edx: 0xd4d4_0000 | u32::from(DATA_OFFSET),
        esp: 0xe5e5_0080, ebp: 0xf6f6_2468, esi: 0x1717_1357, edi: 0x2828_0010,
        eip: 8, eflags: 0x0ed7, cs: return_cs, ds, es: ds, ss, fs: 0x4242, gs: 0x5353,
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

fn enter(runtime: &mut Runtime, route: Route) {
    if let Route::ProtectedInt21 = route {
        let state = runtime.win16.as_mut().unwrap();
        let segments = crate::win16_loader::Win16Segments {
            selectors: &state.selectors, memory_len: runtime.memory.len(),
        };
        assert_eq!(runtime.cpu.step_with_context(&mut runtime.memory.bus(), &mut NoPorts,
            &segments).unwrap(), x86_cpu::StepOutcome::Interrupt(0x21));
        state.begin_software_interrupt(0x21, &mut runtime.cpu, &mut runtime.memory).unwrap();
        assert_eq!(firmware_service_at(state, runtime.cpu.regs.cs,
            runtime.cpu.regs.ip(), &runtime.memory).unwrap(), Some(0x21));
    }
}

fn complete(runtime: &mut Runtime, host: &mut SpoolHost, route: Route) -> Result<(), RuntimeError> {
    match route {
        Route::ProtectedInt21 => {
            let state = runtime.win16.as_mut().unwrap();
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
    let state = runtime.win16.as_mut().unwrap();
    assert!(!state.kernel_file_system.has_active_callback());
    assert!(!state.begin_pending_file_cdr_callback(
        &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, host,
    )?);
    assert_eq!(host.directory_activations, 0);
    Ok(())
}

fn call(runtime: &mut Runtime, host: &mut SpoolHost, route: Route, expected: Registers) {
    let before = runtime.cpu.regs.clone();
    let notices = host.dos_notices.len();
    enter(runtime, route);
    complete(runtime, host, route).unwrap();
    assert_eq!(runtime.cpu.regs, expected, "{route:?}");
    match route {
        Route::ProtectedInt21 => assert_eq!(host.dos_notices.len(), notices),
        Route::Dos3Call => {
            assert_eq!(host.dos_notices.len(), notices + 1);
            assert_eq!(host.dos_notices.last().unwrap(), &(before, expected));
        }
    }
}

fn assert_dos_untouched(host: &SpoolHost) {
    assert_eq!(host.tokens, [HOST_FILE]);
    assert!(host.writes.is_empty());
    assert!(host.closes.is_empty());
    assert!(host.truncations.is_empty());
}

#[test]
fn spool_routes_write_failure_is_available_through_extended_error_without_replaying_io() {
    for route in ROUTES {
        let (mut runtime, mut host, _) = fixture();
        let handle = open_spool(&mut runtime, &mut host);
        host.next_spool_error = Some(5);
        let mut expected = prepare(&mut runtime, route, 0x40, handle, DATA.len() as u16);
        expected.set_ax(5);
        expected.set_carry(true);
        call(&mut runtime, &mut host, route, expected);
        let operations = host.spool_calls.len();
        let mut query = runtime.cpu.regs.clone();
        query.set_ax(0x5900);
        assert_eq!(dispatch_int21(runtime.win16.as_mut().unwrap(), &mut runtime.dos,
            &mut query, &mut runtime.memory, &mut host).unwrap(), DosAction::Continue);
        assert_eq!((query.ax(), query.bx(), query.ch(), query.es, query.di()),
            (5, 0x0303, 1, 0, 0));
        assert!(!query.carry());
        assert_eq!(host.spool_calls.len(), operations);
        assert!(runtime.win16.as_ref().unwrap().network_print_hfile_is_owned(OwnerId(1), handle));
        assert_dos_untouched(&host);
    }
}

#[test]
fn spool_routes_use_wnet_hfile_and_preserve_full_register_return() {
    for route in ROUTES {
        let (mut runtime, mut host, _) = fixture();
        let hfile = open_spool(&mut runtime, &mut host);
        let mut expected = prepare(&mut runtime, route, 0x40, hfile, DATA.len() as u16);
        expected.set_ax(DATA.len() as u16);
        expected.set_carry(false);
        call(&mut runtime, &mut host, route, expected);
        assert_eq!(host.spool_calls, [Win16HostSpoolOperation::Write { job: HOST_JOB, bytes: DATA.to_vec() }]);
        assert_eq!(host.io_notices, [("write", hfile, Some(DATA.len() as u32))]);
        assert_eq!(host.status_calls, 1);
        let mut expected = prepare(&mut runtime, route, 0x3e, hfile, 0xffff);
        runtime.cpu.regs.ds = 0;
        expected.ds = 0; // Close has no caller buffer.
        expected.set_ax(0);
        expected.set_carry(false);
        call(&mut runtime, &mut host, route, expected);
        assert_eq!(host.spool_calls[1], Win16HostSpoolOperation::ReleaseNetworkJob { job: HOST_JOB });
        assert_eq!(host.io_notices[1], ("close", hfile, Some(0)));
        assert_eq!(host.spool_calls.len(), 2);
        assert_eq!(host.io_notices.len(), 2);
        assert_eq!(host.status_calls, 2);
        assert!(!runtime.win16.as_ref().unwrap().network_print_hfile_is_owned(OwnerId(1), hfile));
        assert_dos_untouched(&host);
    }
}

#[test]
fn spool_routes_claim_current_task_alias_before_same_number_dos_handle() {
    for route in ROUTES {
        for owner in [OwnerId(1), OwnerId(2)] {
            for service in [0x3e, 0x40] {
                let (mut runtime, mut host, handle) = fixture();
                install_spool_alias(&mut runtime, owner, handle, false);
                runtime.win16.as_mut().unwrap().tasks.dispatch(owner).unwrap();
                let mut expected = prepare(&mut runtime, route, service, handle, DATA.len() as u16);
                expected.set_ax(if service == 0x3e { 0 } else { DATA.len() as u16 });
                expected.set_carry(false);
                call(&mut runtime, &mut host, route, expected);
                assert_eq!(host.spool_calls, [if service == 0x3e {
                    Win16HostSpoolOperation::ReleaseNetworkJob { job: HOST_JOB }
                } else {
                    Win16HostSpoolOperation::Write { job: HOST_JOB, bytes: DATA.to_vec() }
                }]);
                assert_eq!(host.io_notices.len(), 1);
                assert_eq!(host.status_calls, 1);
                assert_dos_untouched(&host);
            }
        }
    }
}

#[test]
fn spool_routes_protect_hfile_255_from_expanded_dos_jft_collision() {
    for route in ROUTES {
        for service in [0x3e, 0x40] {
            let (mut runtime, mut host, handle) = fixture();
            let hfile = open_spool(&mut runtime, &mut host);
            // Construct a real DOS-owned expanded JFT, then put an unrelated
            // file in its equal-number slot. Protected AH=67 remains unsupported;
            // this is a collision-safety fixture, not a new Win16 resize route.
            let mut regs = Registers::default();
            regs.set_ax(0x6700);
            regs.set_bx(256);
            assert_eq!(runtime.dos.interrupt(0x21, &mut regs, &mut runtime.memory.bus(), &mut host).unwrap(), DosAction::Continue);
            assert!(!regs.carry());
            regs.set_ax(0x4600);
            regs.set_bx(handle);
            regs.set_cx(hfile);
            assert_eq!(runtime.dos.interrupt(0x21, &mut regs, &mut runtime.memory.bus(), &mut host).unwrap(), DosAction::Continue);
            assert!(!regs.carry());
            let tokens = host.tokens.clone();
            let mut expected = prepare(&mut runtime, route, service, hfile, 0);
            runtime.cpu.regs.ds = 0;
            expected.ds = 0;
            expected.set_ax(0);
            expected.set_carry(false);
            call(&mut runtime, &mut host, route, expected);
            assert_eq!(host.spool_calls, [if service == 0x3e {
                Win16HostSpoolOperation::ReleaseNetworkJob { job: HOST_JOB }
            } else {
                Win16HostSpoolOperation::Write { job: HOST_JOB, bytes: vec![] }
            }]);
            assert_eq!(host.tokens, tokens);
            assert!(host.writes.is_empty());
            assert!(host.closes.is_empty());
            assert!(host.truncations.is_empty());
        }
    }
}

#[test]
fn spool_routes_reject_foreign_and_reserved_aliases_without_dos_fallback() {
    for route in ROUTES {
        for (owner, reserved) in [(OwnerId(2), false), (OwnerId(1), true), (OwnerId(2), true)] {
            for service in [0x3e, 0x40] {
                for collision in [false, true] {
                    let (mut runtime, mut host, handle) = fixture();
                    let hfile = if collision { handle } else { 255 };
                    install_spool_alias(&mut runtime, owner, hfile, reserved);
                    let mut expected = prepare(&mut runtime, route, service, hfile, 4);
                    runtime.cpu.regs.ds = 0;
                    expected.ds = 0; // Reject identity before inspecting a buffer.
                    expected.set_ax(DosErrorCode::InvalidHandle as u16);
                    expected.set_carry(true);
                    call(&mut runtime, &mut host, route, expected);
                    assert!(host.spool_calls.is_empty());
                    assert!(host.io_notices.is_empty());
                    assert_eq!(host.status_calls, 1);
                    assert!(runtime.win16.as_ref().unwrap().network_print_hfile_is_owned(owner, hfile));
                    assert_dos_untouched(&host);
                }
            }
        }
    }
}

#[test]
fn spool_routes_preserve_ordinary_dos_write_truncate_close_and_invalid_handle() {
    for route in ROUTES {
        for owner in [OwnerId(1), OwnerId(2)] {
            let (mut runtime, mut host, handle) = fixture();
            // Another alias must not block unrelated ordinary DOS handles.
            install_spool_alias(&mut runtime, OwnerId(1), 255, false);
            runtime.win16.as_mut().unwrap().tasks.dispatch(owner).unwrap();
            let mut expected = prepare(&mut runtime, route, 0x40, handle, DATA.len() as u16);
            expected.set_ax(DATA.len() as u16);
            expected.set_carry(false);
            call(&mut runtime, &mut host, route, expected);
            assert_eq!(host.writes, [(HOST_FILE, DATA.to_vec())]);
            let mut expected = prepare(&mut runtime, route, 0x40, handle, 0);
            runtime.cpu.regs.ds = 0;
            expected.ds = 0;
            expected.set_ax(0);
            expected.set_carry(false);
            call(&mut runtime, &mut host, route, expected);
            assert_eq!(host.truncations, [(HOST_FILE, 7)]);
            let mut expected = prepare(&mut runtime, route, 0x3e, handle, 0xffff);
            expected.set_carry(false); // Ordinary DOS close preserves AX.
            call(&mut runtime, &mut host, route, expected);
            assert_eq!(host.closes, [HOST_FILE]);
            assert!(host.tokens.is_empty());
            for service in [0x3e, 0x40] {
                let mut expected = prepare(&mut runtime, route, service, handle, 4);
                expected.set_ax(DosErrorCode::InvalidHandle as u16);
                expected.set_carry(true);
                call(&mut runtime, &mut host, route, expected);
            }
            assert!(host.spool_calls.is_empty());
            assert!(host.io_notices.is_empty());
        }
    }
}

#[test]
fn spool_routes_zero_length_write_ignores_invalid_data_selector_without_truncation() {
    for route in ROUTES {
        for selector in [0, 0xfff8] {
            let (mut runtime, mut host, handle) = fixture();
            install_spool_alias(&mut runtime, OwnerId(1), handle, false);
            let mut expected = prepare(&mut runtime, route, 0x40, handle, 0);
            runtime.cpu.regs.ds = selector;
            expected.ds = selector;
            expected.set_ax(0);
            expected.set_carry(false);
            call(&mut runtime, &mut host, route, expected);
            assert_eq!(host.spool_calls, [Win16HostSpoolOperation::Write { job: HOST_JOB, bytes: vec![] }]);
            assert_eq!(host.io_notices, [("write", handle, Some(0))]);
            assert_dos_untouched(&host);
        }
    }
}

#[test]
fn spool_routes_validate_nonempty_selector_span_before_host_write() {
    for route in ROUTES {
        for invalid in 0..3 {
            let (mut runtime, mut host, handle) = fixture();
            install_spool_alias(&mut runtime, OwnerId(1), handle, false);
            let _ = prepare(&mut runtime, route, 0x40, handle, DATA.len() as u16);
            match invalid {
                0 => runtime.cpu.regs.ds = 0,
                1 => runtime.cpu.regs.ds = 0xfff8,
                _ => runtime.cpu.regs.set_dx(0xffff),
            }
            enter(&mut runtime, route);
            let before = runtime.cpu.regs.clone();
            assert!(complete(&mut runtime, &mut host, route).is_err());
            assert_eq!(runtime.cpu.regs, before);
            assert!(host.spool_calls.is_empty());
            assert_eq!(host.io_notices, [("write", handle, None)]);
            assert!(host.dos_notices.is_empty());
            assert_eq!(host.status_calls, 0);
            assert!(runtime.win16.as_ref().unwrap().network_print_hfile_is_owned(OwnerId(1), handle));
            assert_dos_untouched(&host);
        }
    }
}

#[test]
fn spool_routes_preserve_native_failure_for_retry_and_report_partial_write() {
    for route in ROUTES {
        for service in [0x3e, 0x40] {
            let (mut runtime, mut host, handle) = fixture();
            install_spool_alias(&mut runtime, OwnerId(1), handle, false);
            let mut expected = prepare(&mut runtime, route, service, handle, DATA.len() as u16);
            host.next_spool_error = Some(5);
            expected.set_ax(if service == 0x3e { 6 } else { 5 });
            expected.set_carry(true);
            call(&mut runtime, &mut host, route, expected);
            assert_eq!(host.spool_calls.len(), 1);
            assert!(runtime.win16.as_ref().unwrap().network_print_hfile_is_owned(OwnerId(1), handle));
            let mut expected = prepare(&mut runtime, route, service, handle, DATA.len() as u16);
            let result = if service == 0x3e { 0 } else { 2 };
            if service == 0x40 { host.next_write_count = Some(result); }
            expected.set_ax(result as u16);
            expected.set_carry(false);
            call(&mut runtime, &mut host, route, expected);
            assert_eq!(host.spool_calls.len(), 2);
            assert_eq!(host.io_notices.len(), 2);
            assert_eq!(host.status_calls, 2);
            assert_eq!(runtime.win16.as_ref().unwrap().network_print_hfile_is_owned(OwnerId(1), handle), service == 0x40);
            assert_dos_untouched(&host);
        }
    }
}

#[test]
fn spool_routes_preflight_corrupt_dos_metadata_before_identity_or_host_mutation() {
    for route in ROUTES {
        for (owner, reserved) in [(OwnerId(1), false), (OwnerId(2), false), (OwnerId(1), true)] {
            for service in [0x3e, 0x40] {
                let (mut runtime, mut host, handle) = fixture();
                install_spool_alias(&mut runtime, owner, handle, reserved);
                let _ = prepare(&mut runtime, route, service, handle, DATA.len() as u16);
                enter(&mut runtime, route);
                let before = runtime.cpu.regs.clone();
                let psp = runtime.dos.psp_segment();
                runtime.memory.write(real_address(psp, 0x34), &[0xff; 4]).unwrap();
                assert!(complete(&mut runtime, &mut host, route).is_err());
                assert_eq!(runtime.cpu.regs, before);
                assert!(host.spool_calls.is_empty());
                assert!(host.io_notices.is_empty());
                assert!(host.dos_notices.is_empty());
                assert_eq!(host.status_calls, 0);
                assert!(runtime.win16.as_ref().unwrap().network_print_hfile_is_owned(owner, handle));
                assert_dos_untouched(&host);
            }
        }
    }
}

#[test]
fn spool_dos3call_preflights_far_return_before_close_or_write() {
    for service in [0x3e, 0x40] {
        for invalid in 0..3 {
            let (mut runtime, mut host, handle) = fixture();
            install_spool_alias(&mut runtime, OwnerId(1), handle, false);
            let _ = prepare(&mut runtime, Route::Dos3Call, service, handle, DATA.len() as u16);
            if invalid == 0 {
                runtime.cpu.regs.ss = 0;
            } else {
                let state = runtime.win16.as_mut().unwrap();
                let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp()).unwrap();
                let mut frame = [0; 4];
                state.selectors.read(&runtime.memory, pointer, &mut frame).unwrap();
                if invalid == 1 { frame[..2].copy_from_slice(&0xffff_u16.to_le_bytes()); }
                else { frame[2..].copy_from_slice(&runtime.cpu.regs.ds.to_le_bytes()); }
                state.selectors.write(&mut runtime.memory, pointer, &frame).unwrap();
            }
            let before = runtime.cpu.regs.clone();
            assert!(complete(&mut runtime, &mut host, Route::Dos3Call).is_err());
            assert_eq!(runtime.cpu.regs, before);
            assert!(host.spool_calls.is_empty());
            assert!(host.io_notices.is_empty());
            assert!(host.dos_notices.is_empty());
            assert_eq!(host.status_calls, 0);
            assert!(runtime.win16.as_ref().unwrap().network_print_hfile_is_owned(OwnerId(1), handle));
            assert_dos_untouched(&host);
        }
    }
}

#[test]
fn spool_routes_keep_completed_host_state_when_dos_refresh_fails() {
    for route in ROUTES {
        for service in [0x3e, 0x40] {
            let (mut runtime, mut host, handle) = fixture();
            install_spool_alias(&mut runtime, OwnerId(1), handle, false);
            let _ = prepare(&mut runtime, route, service, handle, DATA.len() as u16);
            enter(&mut runtime, route);
            let mut expected = runtime.cpu.regs.clone();
            expected.set_ax(if service == 0x3e { 0 } else { DATA.len() as u16 });
            expected.set_carry(false);
            host.next_status_error = Some(DosErrorCode::GeneralFailure);
            assert!(complete(&mut runtime, &mut host, route).is_err());
            // A terminal metadata error leaves the checked return pending,
            // but cannot restore a retired alias or roll back written bytes.
            assert_eq!(runtime.cpu.regs, expected);
            assert_eq!(host.spool_calls.len(), 1);
            assert_eq!(host.io_notices.len(), 1);
            assert!(host.dos_notices.is_empty());
            assert_eq!(host.status_calls, 1);
            assert_eq!(runtime.win16.as_ref().unwrap().network_print_hfile_is_owned(OwnerId(1), handle), service == 0x40);
            // Repair only the independent projection, never redispatch I/O.
            runtime.dos.finish_external_int21(&mut runtime.memory, &mut host).unwrap();
            assert_eq!(host.spool_calls.len(), 1);
            assert_eq!(host.io_notices.len(), 1);
            assert_dos_untouched(&host);
        }
    }
}
