//! AH=40h read-only denial before protected caller-buffer access on both routes.

use super::{dispatch_int21, firmware_service_at, resolve_interrupt_target};
use super::super::{
    ImportBinding, interrupt_entry,
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
use guest_core::{GuestMemory, OwnerId, Registers, Selector, io::NoPorts, real_address};
use win16_abi::{Access, ExportLookupTarget, Win16KernelFileSystemRequest, lookup_export};

const HOST_FILE: DosHostFile = DosHostFile(0x1234);
const RETURN_IP: u16 = 0x12;
const DATA_OFFSET: u16 = 0x20;

struct WriteAccessHost {
    access: DosFileAccess,
    tokens: Vec<DosHostFile>,
    directory_activations: usize,
    status_calls: Vec<DosHostFile>,
}

impl DosHost for WriteAccessHost {
    fn file_ioctl_info(&self, file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        assert!(self.tokens.contains(&file));
        Ok(DosIoctlObjectInfo::File { drive: 2, written: false })
    }
    fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        assert!(self.tokens.contains(&file));
        self.status_calls.push(file);
        Ok(DosFileStatus {
            short_name: *b"WRITE   DAT", size: 0x1020, position: 7,
            attributes: 0x20, write_time: 0, write_date: 0,
        })
    }
    fn read_stdin(&mut self, _output: &mut [u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn try_read_stdin(&mut self) -> Result<Option<u8>, DosHostError> { panic!("unexpected host call") }
    fn write_stdout(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn write_stderr(&mut self, _input: &[u8]) -> Result<usize, DosHostError> { panic!("unexpected host call") }
    fn flush_stdin(&mut self) -> Result<(), DosHostError> { panic!("unexpected host call") }
    fn file_create(&mut self, _path: &[u8], _attributes: u8) -> Result<DosHostFile, DosHostError> { panic!("unexpected host call") }
    fn file_open(&mut self, path: &[u8], access: DosFileAccess) -> Result<DosHostFile, DosHostError> {
        assert_eq!(path, b"WRITE.DAT");
        assert_eq!(access, self.access);
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

impl RuntimeHost for WriteAccessHost {
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
        panic!("write must not resolve paths or capture FileCDR notices")
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for WriteAccessHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for WriteAccessHost {}
impl crate::RuntimeMidiHost for WriteAccessHost {}
impl crate::RuntimeNetbiosHost for WriteAccessHost {}

#[derive(Clone, Copy, Debug)]
enum Route {
    ProtectedInt21,
    Dos3Call,
}

const ROUTES: [Route; 2] = [Route::ProtectedInt21, Route::Dos3Call];

fn fixture(mode: u8) -> (Runtime, WriteAccessHost, u16) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\WRITE.NE").unwrap();
    let mut host = WriteAccessHost {
        access: match mode { 0 => DosFileAccess::ReadOnly, 1 => DosFileAccess::WriteOnly,
            2 => DosFileAccess::ReadWrite, _ => panic!("unsupported fixture mode") },
        tokens: Vec::new(), directory_activations: 0, status_calls: Vec::new(),
    };
    let state = runtime.win16.as_mut().unwrap();
    state.kernel_file_system.seed_owner(OwnerId(1), Win16CanonicalPath {
        drive: 2, components: vec!["FILES".to_owned()],
    }).unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0x20).unwrap();
    let address = state.selectors.translate(pointer, Access::Read, 10, &runtime.memory).unwrap();
    assert_ne!(address, real_address(runtime.cpu.regs.ds, 0x20));
    state.selectors.write(&mut runtime.memory, pointer, b"WRITE.DAT\0").unwrap();
    runtime.cpu.regs.set_ax(0x3d00 | u16::from(mode)); // Open the DOS handle through the caller's selector.
    runtime.cpu.regs.set_dx(0x20);
    assert_eq!(dispatch_int21(state, &mut runtime.dos, &mut runtime.cpu.regs, &mut runtime.memory, &mut host).unwrap(), DosAction::Continue);
    assert!(!runtime.cpu.regs.carry());
    let handle = runtime.cpu.regs.ax();
    assert_eq!(host.tokens, [HOST_FILE]);
    assert_eq!(host.status_calls, [HOST_FILE]);

    let code = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.cs), 8).unwrap();
    let code = state.selectors.translate(code, Access::Execute, 2, &runtime.memory).unwrap();
    runtime.memory.write(code, &[0xcd, 0x21]).unwrap();
    resolve_interrupt_target(state, 0x21, &mut runtime.memory).unwrap();
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

fn complete(runtime: &mut Runtime, host: &mut WriteAccessHost, route: Route) -> Result<(), RuntimeError> {
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

fn invalidate_buffer(runtime: &mut Runtime, expected: &mut Registers, invalid: u8) {
    match invalid {
        0 | 1 => {
            let selector = if invalid == 0 { 0 } else { 0xfff8 };
            assert!(runtime.win16.as_ref().unwrap().selectors
                .pointer_from_raw(Selector(selector), 0).is_err());
            runtime.cpu.regs.ds = selector;
            expected.ds = selector;
        }
        _ => {
            let state = runtime.win16.as_ref().unwrap();
            let invalid_span = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), 0xffff)
                .and_then(|pointer| state.selectors.translate(pointer, Access::Read, 1, &runtime.memory));
            assert!(invalid_span.is_err());
            runtime.cpu.regs.set_dx(0xffff);
            expected.set_dx(0xffff);
        }
    }
}

fn deny_write(runtime: &mut Runtime, host: &mut WriteAccessHost, route: Route, handle: u16,
    count: u16, invalid: u8) {
    let mut expected = prepare(runtime, route, 0x40, handle, count);
    invalidate_buffer(runtime, &mut expected, invalid);
    // DOS 4 DISK.ASM rejects accessmode=0 before SETUP, even for CX=0.
    // Start with CF clear so this checks the route actually reports an error.
    runtime.cpu.regs.set_carry(false);
    expected.set_ax(DosErrorCode::AccessDenied as u16);
    expected.set_carry(true);
    host.status_calls.clear();
    enter(runtime, route);
    complete(runtime, host, route).unwrap();
    // Includes preserved high halves, non-CF flags and the INT/IRET or checked
    // DOS3Call far-return adjustment. Any host I/O panics in WriteAccessHost.
    assert_eq!(runtime.cpu.regs, expected, "{route:?}, CX={count}, invalid={invalid}");
    assert_eq!(host.status_calls, host.tokens); // Normal DOS metadata refresh only.
}

#[test]
fn file_write_access_routes_deny_readonly_before_invalid_buffer_for_zero_and_nonzero_count() {
    for route in ROUTES {
        for count in [0, 1] {
            for invalid in 0..3 {
                let (mut runtime, mut host, handle) = fixture(0);
                deny_write(&mut runtime, &mut host, route, handle, count, invalid);
                assert_eq!(host.tokens, [HOST_FILE]);
                runtime.dos.close_all_handles_checked(&mut host).unwrap();
                assert!(host.tokens.is_empty());
            }
        }
    }
}

#[test]
fn file_write_access_routes_keep_readonly_mode_for_duplicate_in_standard_slot_after_close() {
    for route in ROUTES {
        for count in [0, 1] {
            let (mut runtime, mut host, handle) = fixture(0);
            runtime.cpu.regs.set_ax(0x4600);
            runtime.cpu.regs.set_bx(handle);
            runtime.cpu.regs.set_cx(0);
            assert_eq!(dispatch_int21(runtime.win16.as_mut().unwrap(), &mut runtime.dos,
                &mut runtime.cpu.regs, &mut runtime.memory, &mut host).unwrap(), DosAction::Continue);
            assert!(!runtime.cpu.regs.carry());
            let duplicate = *host.tokens.last().unwrap();
            assert_ne!(duplicate, HOST_FILE);
            runtime.cpu.regs.set_ax(0x3e00);
            runtime.cpu.regs.set_bx(handle);
            assert_eq!(dispatch_int21(runtime.win16.as_mut().unwrap(), &mut runtime.dos,
                &mut runtime.cpu.regs, &mut runtime.memory, &mut host).unwrap(), DosAction::Continue);
            assert!(!runtime.cpu.regs.carry());
            assert_eq!(host.tokens, [duplicate]);
            deny_write(&mut runtime, &mut host, route, 0, count, 0);
            assert_eq!(host.tokens, [duplicate]);
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
            assert!(host.tokens.is_empty());
        }
    }
}

#[test]
fn file_write_access_routes_still_fault_on_invalid_nonempty_writable_buffer() {
    for route in ROUTES {
        for mode in [1, 2] {
            for invalid in 0..3 {
                let (mut runtime, mut host, handle) = fixture(mode);
                let mut expected = prepare(&mut runtime, route, 0x40, handle, 1);
                invalidate_buffer(&mut runtime, &mut expected, invalid);
                enter(&mut runtime, route);
                let before = runtime.cpu.regs.clone();
                let error = complete(&mut runtime, &mut host, route).unwrap_err();
                assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault);
                assert_eq!(runtime.cpu.regs, before);
                assert_eq!(host.tokens, [HOST_FILE]);
                assert!(host.status_calls.is_empty());
                runtime.dos.close_all_handles_checked(&mut host).unwrap();
            }
        }
    }
}
