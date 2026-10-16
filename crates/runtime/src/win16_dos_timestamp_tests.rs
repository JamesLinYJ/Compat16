//! Owned DOS timestamps through protected INT 21h and KERNEL DOS3Call.

use super::dispatch_int21;
use super::super::{
    ImportBinding,
    kernel_register_calls::{self, Win16KernelRegisterService},
    test_support::{NoHost, tiny_ne_executable},
};
use crate::{Runtime, RuntimeError, RuntimeHost, Win16CanonicalPath, Win16GuestPath};
use devices::{keyboard::KeyStroke, video::ConsoleSnapshot};
use dos_kernel::{
    DosAction, DosDirectoryEntry, DosError, DosErrorCode, DosFileAccess, DosFileSharing,
    DosFileStatus, DosHost, DosHostError, DosHostFile, DosHostSearch,
    DosIoctlObjectInfo, DosSeekOrigin,
};
use guest_core::{GuestMemory, OwnerId, Registers, Selector, real_address};
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
    set_time_calls: Vec<(DosHostFile, u16, u16)>,
    next_set_time_error: Option<DosErrorCode>,
    changed_timestamp: Option<(u16, u16)>,
}

impl DosHost for TimestampHost {
    fn file_ioctl_info(&self, file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        assert_eq!(file, HOST_FILE);
        assert!(self.open);
        Ok(DosIoctlObjectInfo::File { drive: 2, written: self.changed_timestamp.is_some() })
    }
    fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        assert_eq!(file, HOST_FILE);
        assert!(self.open);
        self.status_calls.push(file);
        // Fail one service query or SFT refresh without losing the open file.
        if let Some(code) = self.next_status_error.take() {
            return Err(DosHostError::new(code));
        }
        let (write_time, write_date) = self.changed_timestamp.unwrap_or((WRITE_TIME, WRITE_DATE));
        Ok(DosFileStatus {
            short_name: *b"STAMP   DAT", size: 0x1020, position: 7,
            attributes: 0x21, write_time, write_date,
        })
    }
    fn file_set_write_time(&mut self, file: DosHostFile, time: u16, date: u16) -> Result<(), DosHostError> {
        assert_eq!(file, HOST_FILE);
        assert!(self.open);
        self.set_time_calls.push((file, time, date));
        if let Some(code) = self.next_set_time_error.take() {
            return Err(DosHostError::new(code));
        }
        self.changed_timestamp = Some((time, date));
        Ok(())
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
        panic!("timestamp operations must not resolve paths or capture FileCDR notices")
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

fn invoke(runtime: &mut Runtime, host: &mut TimestampHost, route: Route) -> Result<(), RuntimeError> {
    match route {
        Route::ProtectedInt21 => {
            assert_eq!(dispatch_int21(
                runtime.win16.as_mut().unwrap(), &mut runtime.dos,
                &mut runtime.cpu.regs, &mut runtime.memory, host,
            )?, DosAction::Continue);
        }
        Route::Dos3Call => {
            let service = runtime.win16.as_ref().unwrap()
                .kernel_register_service_at(&runtime.cpu.regs).unwrap().unwrap();
            assert_eq!(service, Win16KernelRegisterService::Dos3Call);
            assert_eq!(kernel_register_calls::dispatch(runtime, service, host, 0)?, None);
        }
    }
    Ok(())
}

fn call(runtime: &mut Runtime, host: &mut TimestampHost, route: Route, expected: Registers, status_calls: usize) {
    let setter_requested = runtime.cpu.regs.ax() == 0x5701;
    let setter_calls_before = host.set_time_calls.len();
    invoke(runtime, host, route).unwrap();
    if !setter_requested {
        assert_eq!(host.set_time_calls.len(), setter_calls_before);
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
        for subfunction in [2, 0xff] {
            let (mut runtime, mut host, handle) = fixture();
            let mut expected = prepare(&mut runtime, route, handle, subfunction);
            use_invalid_data_selectors(&mut runtime, &mut expected, 0);
            runtime.cpu.regs.set_carry(false);
            expected.set_ax(DosErrorCode::InvalidFunction as u16);
            expected.set_carry(true);
            // Refresh-only: no setter or service-level timestamp query.
            call(&mut runtime, &mut host, route, expected, 1);
            assert!(host.set_time_calls.is_empty());
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
    }
}

fn prepare_set(runtime: &mut Runtime, route: Route, handle: u16, time: u16, date: u16) -> Registers {
    let mut expected = prepare(runtime, route, handle, 1);
    runtime.cpu.regs.set_cx(time);
    runtime.cpu.regs.set_dx(date);
    expected.set_cx(time);
    expected.set_dx(date);
    expected
}

fn install_alias_collision(runtime: &mut Runtime, handle: u16, alias_kind: u8) {
    let state = runtime.win16.as_mut().unwrap();
    match alias_kind {
        0 => {}
        1 => { state.files.insert(handle, crate::Win16HostFile(0x5678)); }
        2 | 3 => {
            let owner = if alias_kind == 2 { OwnerId(1) } else { OwnerId(2) };
            state.network_print_jobs.entry(owner).or_default().insert_open_job(
                handle, crate::Win16HostSpoolJob::new(0x6789), b"QUEUE".to_vec(), None,
            ).unwrap();
        }
        _ => panic!("unknown test alias kind"),
    }
}

fn dos_metadata(runtime: &Runtime) -> Vec<u8> {
    let psp = runtime.dos.psp_segment();
    let mut bytes = vec![0; dos_kernel::SYSTEM_BYTES + 0x100 + 16];
    let (system, process) = bytes.split_at_mut(dos_kernel::SYSTEM_BYTES);
    let (psp_bytes, mcb) = process.split_at_mut(0x100);
    runtime.memory.read(real_address(dos_kernel::SYSTEM_SEGMENT, 0), system).unwrap();
    runtime.memory.read(real_address(psp, 0), psp_bytes).unwrap();
    runtime.memory.read(real_address(psp - 1, 0), mcb).unwrap();
    bytes
}

fn published_timestamp(runtime: &Runtime, handle: u16) -> (u16, u16, bool) {
    let psp = runtime.dos.psp_segment();
    let memory = &runtime.memory;
    let jft_offset = memory.read_u16(real_address(psp, 0x34)).unwrap();
    let jft_segment = memory.read_u16(real_address(psp, 0x36)).unwrap();
    let index = memory.read_u8(real_address(jft_segment, jft_offset + handle)).unwrap();
    assert_ne!(index, 0xff);
    // Follow the installed LoL's SFT pointer. DOS 4 SF.INC uses a six-byte
    // table header, 59-byte records, and a clean flag at bit 6 of device info.
    let sft_offset = memory.read_u16(real_address(dos_kernel::SYSTEM_SEGMENT, 0x1c)).unwrap();
    let sft_segment = memory.read_u16(real_address(dos_kernel::SYSTEM_SEGMENT, 0x1e)).unwrap();
    let record = sft_offset + 6 + u16::from(index) * 59;
    let device_info = memory.read_u16(real_address(sft_segment, record + 5)).unwrap();
    let time = memory.read_u16(real_address(sft_segment, record + 13)).unwrap();
    let date = memory.read_u16(real_address(sft_segment, record + 15)).unwrap();
    (time, date, device_info & 0x40 == 0)
}

#[test]
fn timestamp_write_default_host_contract_is_explicitly_unsupported() {
    let error = NoHost.file_set_write_time(HOST_FILE, WRITE_TIME, WRITE_DATE).unwrap_err();
    assert_eq!(error.code, DosErrorCode::InvalidFunction);
}

#[test]
fn timestamp_write_routes_preserve_registers_and_raw_words_with_invalid_data_selectors() {
    for route in ROUTES {
        for selector in [0, 0xfff8] {
            // Validation belongs to the host, so even zero or malformed packed
            // fields must arrive unchanged rather than be treated as pointers.
            for (time, date) in [(0, 0), (WRITE_TIME, WRITE_DATE), (0xffff, 0xffff)] {
                let (mut runtime, mut host, handle) = fixture();
                let mut expected = prepare_set(&mut runtime, route, handle, time, date);
                use_invalid_data_selectors(&mut runtime, &mut expected, selector);
                expected.set_carry(false);
                call(&mut runtime, &mut host, route, expected, 1);
                assert_eq!(host.set_time_calls, [(HOST_FILE, time, date)]);
                assert_eq!(host.changed_timestamp, Some((time, date)));
                assert_eq!(published_timestamp(&runtime, handle), (time, date, true));
                assert!(host.open); // The read-only DOS handle remains owned.
                runtime.dos.close_all_handles_checked(&mut host).unwrap();
                assert!(!host.open);
            }
        }
    }
}

#[test]
fn timestamp_write_routes_do_not_activate_directory_or_capture_file_cdr_paths() {
    assert!(!super::needs_dos_directory_context(0x57));
    for route in ROUTES {
        let (mut runtime, mut host, handle) = fixture();
        let mut expected = prepare(&mut runtime, route, handle, 1);
        // DS:DX still names STAMP.DAT and FileCDR has an executable callback.
        // A path-based implementation would reach the host's panic above.
        expected.set_carry(false);
        call(&mut runtime, &mut host, route, expected, 1);
        assert_eq!(host.set_time_calls, [(HOST_FILE, 0x4567, 0x0020)]);
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
    }
}

#[test]
fn timestamp_write_routes_return_host_errors_and_retain_handle_for_retry() {
    for route in ROUTES {
        for code in [DosErrorCode::AccessDenied, DosErrorCode::InvalidData,
            DosErrorCode::InvalidFunction, DosErrorCode::GeneralFailure] {
            let (mut runtime, mut host, handle) = fixture();
            let mut expected = prepare_set(&mut runtime, route, handle, WRITE_TIME, WRITE_DATE);
            use_invalid_data_selectors(&mut runtime, &mut expected, 0);
            runtime.cpu.regs.set_carry(false);
            host.next_set_time_error = Some(code);
            expected.set_ax(code as u16);
            expected.set_carry(true);
            call(&mut runtime, &mut host, route, expected, 1);
            assert_eq!(host.set_time_calls, [(HOST_FILE, WRITE_TIME, WRITE_DATE)]);
            assert!(host.next_set_time_error.is_none());
            assert_eq!(host.changed_timestamp, None);
            assert!(host.open);

            host.set_time_calls.clear();
            host.status_calls.clear();
            let mut expected = prepare_set(&mut runtime, route, handle, WRITE_TIME, WRITE_DATE);
            expected.set_carry(false);
            call(&mut runtime, &mut host, route, expected, 1);
            assert_eq!(host.set_time_calls, [(HOST_FILE, WRITE_TIME, WRITE_DATE)]);
            assert_eq!(host.changed_timestamp, Some((WRITE_TIME, WRITE_DATE)));
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
    }
}

#[test]
fn timestamp_write_routes_reject_missing_standard_and_closed_handles_without_mutation() {
    for route in ROUTES {
        for (handle, code) in [(0xffff, DosErrorCode::InvalidHandle),
            (0, DosErrorCode::InvalidFunction), (1, DosErrorCode::InvalidFunction),
            (2, DosErrorCode::InvalidFunction)] {
            let (mut runtime, mut host, _) = fixture();
            let mut expected = prepare_set(&mut runtime, route, handle, WRITE_TIME, WRITE_DATE);
            use_invalid_data_selectors(&mut runtime, &mut expected, 0xfff8);
            runtime.cpu.regs.set_carry(false);
            expected.set_ax(code as u16);
            expected.set_carry(true);
            call(&mut runtime, &mut host, route, expected, 1);
            assert!(host.set_time_calls.is_empty());
            assert_eq!(host.changed_timestamp, None);
            assert!(host.open);
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
        let (mut runtime, mut host, handle) = fixture();
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
        let mut expected = prepare_set(&mut runtime, route, handle, WRITE_TIME, WRITE_DATE);
        use_invalid_data_selectors(&mut runtime, &mut expected, 0);
        runtime.cpu.regs.set_carry(false);
        expected.set_ax(DosErrorCode::InvalidHandle as u16);
        expected.set_carry(true);
        call(&mut runtime, &mut host, route, expected, 0);
        assert!(host.set_time_calls.is_empty());
        assert_eq!(host.changed_timestamp, None);
        assert!(!host.open);
    }
}

#[test]
fn timestamp_write_routes_reject_win16_and_cross_task_spool_alias_collisions() {
    for route in ROUTES {
        for alias_kind in 1..=3 {
            let (mut runtime, mut host, handle) = fixture();
            // Deliberately collide exact numbers instead of relying on the
            // ordinary HFILE allocator's separation from DOS handle numbers.
            install_alias_collision(&mut runtime, handle, alias_kind);
            let mut expected = prepare_set(&mut runtime, route, handle, WRITE_TIME, WRITE_DATE);
            use_invalid_data_selectors(&mut runtime, &mut expected, 0);
            runtime.cpu.regs.set_carry(false);
            expected.set_ax(DosErrorCode::InvalidFunction as u16);
            expected.set_carry(true);
            call(&mut runtime, &mut host, route, expected, 1);
            assert!(host.set_time_calls.is_empty());
            assert_eq!(host.changed_timestamp, None);
            assert!(host.open);

            let state = runtime.win16.as_mut().unwrap();
            state.files.clear();
            state.network_print_jobs.clear();
            host.status_calls.clear();
            let mut expected = prepare_set(&mut runtime, route, handle, WRITE_TIME, WRITE_DATE);
            expected.set_carry(false);
            call(&mut runtime, &mut host, route, expected, 1);
            assert_eq!(host.set_time_calls, [(HOST_FILE, WRITE_TIME, WRITE_DATE)]);
            assert_eq!(host.changed_timestamp, Some((WRITE_TIME, WRITE_DATE)));
            runtime.dos.close_all_handles_checked(&mut host).unwrap();
        }
    }
}

#[test]
fn timestamp_write_routes_preflight_jft_and_mcb_before_host_or_collision_result() {
    for route in ROUTES {
        for alias_kind in 0..=3 {
            for corrupt_mcb in [false, true] {
                let (mut runtime, mut host, handle) = fixture();
                install_alias_collision(&mut runtime, handle, alias_kind);
                let _ = prepare_set(&mut runtime, route, handle, WRITE_TIME, WRITE_DATE);
                let before = runtime.cpu.regs.clone();
                let psp = runtime.dos.psp_segment();
                if corrupt_mcb {
                    runtime.memory.write(real_address(psp - 1, 0), b"X").unwrap();
                } else {
                    runtime.memory.write(real_address(psp, 0x34), &[0xff; 4]).unwrap();
                }
                let metadata_before = dos_metadata(&runtime);
                let error = invoke(&mut runtime, &mut host, route).unwrap_err();
                assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault);
                let cause = error.diagnostic().cause().unwrap().downcast_ref::<DosError>().unwrap();
                if corrupt_mcb {
                    assert!(matches!(cause, DosError::InvalidMcbSignature { .. }));
                } else {
                    assert!(matches!(cause, DosError::MalformedGuestInput(_)));
                }
                assert_eq!(runtime.cpu.regs, before, "{route:?}, alias={alias_kind}");
                assert_eq!(dos_metadata(&runtime), metadata_before);
                assert!(host.set_time_calls.is_empty());
                assert!(host.status_calls.is_empty());
                assert_eq!(host.changed_timestamp, None);
                assert_eq!(host.directory_activations, 0);
                assert!(!runtime.win16.as_ref().unwrap().kernel_file_system.has_active_callback());
                assert!(host.open);
                runtime.dos.close_all_handles_checked(&mut host).unwrap();
                assert!(!host.open);
            }
        }
    }
}

#[test]
fn timestamp_write_dos3call_validates_far_return_before_mutation() {
    for invalid_return in 0..3 {
        let (mut runtime, mut host, handle) = fixture();
        let _ = prepare_set(&mut runtime, Route::Dos3Call, handle, WRITE_TIME, WRITE_DATE);
        if invalid_return == 0 {
            runtime.cpu.regs.ss = 0;
        } else {
            let state = runtime.win16.as_mut().unwrap();
            let stack = state.selectors.pointer_from_raw(
                Selector(runtime.cpu.regs.ss), runtime.cpu.regs.sp() + 2,
            ).unwrap();
            // A NULL code selector or data-only selector cannot be returned to.
            let return_cs = if invalid_return == 1 { 0 } else { runtime.cpu.regs.ds };
            state.selectors.write(&mut runtime.memory, stack, &return_cs.to_le_bytes()).unwrap();
        }
        let before = runtime.cpu.regs.clone();
        let metadata_before = dos_metadata(&runtime);
        let error = invoke(&mut runtime, &mut host, Route::Dos3Call).unwrap_err();
        assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault);
        assert_eq!(runtime.cpu.regs, before);
        assert_eq!(dos_metadata(&runtime), metadata_before);
        assert!(host.set_time_calls.is_empty());
        assert!(host.status_calls.is_empty());
        assert_eq!(host.changed_timestamp, None);
        assert_eq!(host.directory_activations, 0);
        assert!(host.open);
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
        assert!(!host.open);
    }
}

#[test]
fn timestamp_write_routes_keep_mutation_and_handle_after_typed_sft_refresh_error() {
    for route in ROUTES {
        let (mut runtime, mut host, handle) = fixture();
        let time = WRITE_TIME ^ 1;
        let date = WRITE_DATE + 1;
        let _ = prepare_set(&mut runtime, route, handle, time, date);
        // The host mutation succeeds, but the later publication query fails.
        // DOS3Call must not perform its far return on this runtime failure.
        let mut expected = runtime.cpu.regs.clone();
        expected.set_carry(false);
        let metadata_before = dos_metadata(&runtime);
        assert_eq!(published_timestamp(&runtime, handle), (WRITE_TIME, WRITE_DATE, false));
        host.next_status_error = Some(DosErrorCode::GeneralFailure);
        let error = invoke(&mut runtime, &mut host, route).unwrap_err();
        assert_eq!(error.kind(), crate::DiagnosticKind::HostFailure);
        let cause = error.diagnostic().cause().unwrap().downcast_ref::<DosError>().unwrap();
        assert!(matches!(cause, DosError::HostOperation(error)
            if error.code == DosErrorCode::GeneralFailure));
        assert_eq!(runtime.cpu.regs, expected);
        assert_eq!(host.set_time_calls, [(HOST_FILE, time, date)]);
        assert_eq!(host.status_calls, [HOST_FILE]);
        assert_eq!(host.changed_timestamp, Some((time, date)));
        assert_eq!(dos_metadata(&runtime), metadata_before);
        assert_eq!(published_timestamp(&runtime, handle), (WRITE_TIME, WRITE_DATE, false));
        assert_eq!(host.directory_activations, 0);
        assert!(host.open);
        assert!(!runtime.win16.as_ref().unwrap().kernel_file_system.has_active_callback());

        // Recover just the SFT publication without repeating the mutation.
        runtime.dos.finish_external_int21(&mut runtime.memory, &mut host).unwrap();
        assert_eq!(host.set_time_calls, [(HOST_FILE, time, date)]);
        assert_eq!(host.status_calls, [HOST_FILE, HOST_FILE]);
        assert_ne!(dos_metadata(&runtime), metadata_before);
        assert_eq!(published_timestamp(&runtime, handle), (time, date, true));
        assert_eq!(host.changed_timestamp, Some((time, date)));
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
        assert!(!host.open); // The failed refresh did not orphan the DOS token.
    }
}
