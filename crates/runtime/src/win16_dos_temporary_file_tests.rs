//! DOS temporary creation through protected INT/IRET and KERNEL DOS3Call.

use super::{firmware_service_at, resolve_interrupt_target};
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
use guest_core::{GuestMemory, OwnerId, Registers, Selector, io::NoPorts};
use win16_abi::{Access, AccessRights, ExportLookupTarget, Win16KernelFileSystemRequest, lookup_export};

const PATH_OFFSET: u16 = 0x40;
const RETURN_IP: u16 = 0x12;

#[derive(Default)]
struct TemporaryFileHost {
    active: Option<(OwnerId, Win16CanonicalPath)>,
    calls: Vec<(OwnerId, Win16CanonicalPath, Vec<u8>, u8)>,
    files: Vec<(Win16CanonicalPath, Vec<u8>, u8)>,
    handles: Vec<(DosHostFile, usize)>,
    next_handle: u64,
    error: Option<DosErrorCode>,
}

impl DosHost for TemporaryFileHost {
    fn local_date_time(&mut self) -> Result<dos_kernel::DosLocalDateTime, DosHostError> {
        Ok(dos_kernel::DosLocalDateTime {
            year: 1991, month: 6, day: 3, weekday: 1,
            hour: 12, minute: 34, second: 56, hundredth: 78,
        })
    }
    fn file_create_new(&mut self, path: &[u8], attributes: u8) -> Result<DosHostFile, DosHostError> {
        let (owner, directory) = self.active.clone().expect("task directory must be activated first");
        self.calls.push((owner, directory.clone(), path.to_vec(), attributes));
        if let Some(code) = self.error { return Err(DosHostError::new(code)); }
        if self.files.iter().any(|entry| entry.0 == directory && entry.1 == path) {
            return Err(DosHostError::new(DosErrorCode::FileExists));
        }
        self.files.push((directory, path.to_vec(), attributes));
        self.next_handle += 1;
        let file = DosHostFile(self.next_handle);
        self.handles.push((file, self.files.len() - 1));
        Ok(file)
    }
    fn file_ioctl_info(&self, file: DosHostFile) -> Result<DosIoctlObjectInfo, DosHostError> {
        let entry = self.handles.iter().find(|entry| entry.0 == file)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        Ok(DosIoctlObjectInfo::File { drive: self.files[entry.1].0.drive, written: false })
    }
    fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        let entry = self.handles.iter().find(|entry| entry.0 == file)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        let path = &self.files[entry.1].1;
        let mut short_name = [b' '; 11];
        short_name[..8].copy_from_slice(&path[path.len() - 8..]);
        Ok(DosFileStatus {
            short_name, size: 0, position: 0,
            attributes: self.files[entry.1].2, write_time: 0, write_date: 0,
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
        let index = self.handles.iter().position(|entry| entry.0 == file)
            .ok_or_else(|| DosHostError::new(DosErrorCode::InvalidHandle))?;
        self.handles.remove(index);
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

impl RuntimeHost for TemporaryFileHost {
    fn activate_win16_dos_directory(
        &mut self, owner: OwnerId, path: &Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        self.active = Some((owner, path.clone()));
        Ok(())
    }
    fn normalize_win16_dos_path(
        &mut self, _owner: OwnerId, _path: &Win16GuestPath,
    ) -> Result<Option<Win16CanonicalPath>, RuntimeError> {
        panic!("AH=5Ah has no verified generated-path FileCDR notification contract")
    }
    fn epoch_seconds(&self) -> i64 { panic!("unexpected host call") }
    fn read_bios_key(&mut self) -> Result<KeyStroke, RuntimeError> { panic!("unexpected host call") }
    fn render_text(&mut self, _screen: &ConsoleSnapshot) -> Result<(), RuntimeError> { panic!("unexpected host call") }
}
impl crate::RuntimeDdeHost for TemporaryFileHost {
    fn win16_dde_abort(&mut self) -> crate::Win16DdeAbortReceipt { panic!("unexpected host call") }
}
impl crate::RuntimeMciHost for TemporaryFileHost {}
impl crate::RuntimeMidiHost for TemporaryFileHost {}
impl crate::RuntimeNetbiosHost for TemporaryFileHost {}

#[derive(Clone, Copy, Debug)]
enum Route {
    ProtectedInt21,
    Dos3Call,
}

const ROUTES: [Route; 2] = [Route::ProtectedInt21, Route::Dos3Call];

fn fixture() -> (Runtime, TemporaryFileHost) {
    let mut runtime = Runtime::load(&tiny_ne_executable(), &[], br"C:\TEMP.NE").unwrap();
    let mut host = TemporaryFileHost::default();
    let state = runtime.win16.as_mut().unwrap();
    state.tasks.create(OwnerId(2), Some(OwnerId(1))).unwrap();
    for (owner, directory) in [(OwnerId(1), "TASK_A"), (OwnerId(2), "TASK_B")] {
        state.kernel_file_system.seed_owner(owner, Win16CanonicalPath {
            drive: 2, components: vec![directory.to_owned()],
        }).unwrap();
    }
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), PATH_OFFSET).unwrap();
    let address = state.selectors.translate(pointer, Access::Read, 15, &runtime.memory).unwrap();
    assert_ne!(address, guest_core::real_address(runtime.cpu.regs.ds, PATH_OFFSET));
    state.selectors.write(&mut runtime.memory, pointer, b".\\\0").unwrap();
    let mut real_bytes = [0; 15];
    runtime.memory.read(guest_core::real_address(runtime.cpu.regs.ds, PATH_OFFSET), &mut real_bytes).unwrap();
    assert_ne!(&real_bytes[..3], b".\\\0");
    let code = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.cs), 8).unwrap();
    let address = state.selectors.translate(code, Access::Execute, 2, &runtime.memory).unwrap();
    runtime.memory.write(address, &[0xcd, 0x21]).unwrap();
    // Resolve the firmware alias now, before tests deliberately free DS slots.
    resolve_interrupt_target(state, 0x21, &mut runtime.memory).unwrap();
    let procedure = (u32::from(runtime.cpu.regs.cs) << 16) | 0x30;
    assert_eq!(state.execute_kernel_file_system(
        Win16KernelFileSystemRequest::FileCdr { procedure }, &mut runtime.memory, &mut host,
    ).unwrap(), 1);
    assert_eq!(state.kernel_file_system.file_cdr_query(), procedure);
    (runtime, host)
}

fn prepare(runtime: &mut Runtime, route: Route, owner: OwnerId) -> Registers {
    let ds = runtime.cpu.regs.ds;
    let ss = runtime.cpu.regs.ss;
    let return_cs = runtime.cpu.regs.cs;
    let state = runtime.win16.as_mut().unwrap();
    state.tasks.dispatch(owner).unwrap();
    runtime.cpu.regs = Registers {
        eax: 0xa1a1_5a00, ebx: 0xb2b2_20c2,
        ecx: 0xc3c3_0002, edx: 0xd4d4_0000 | u32::from(PATH_OFFSET),
        esp: 0xe5e5_0080, ebp: 0xf6f6_2468, esi: 0x1717_0010,
        edi: 0x2828_0010, eip: 8, eflags: 0x0ed7,
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

fn call(runtime: &mut Runtime, host: &mut TemporaryFileHost, route: Route) -> Result<(), RuntimeError> {
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
            assert!(!state.begin_pending_file_cdr_callback(
                &mut runtime.cpu, &mut runtime.dos, &mut runtime.memory, host,
            )?);
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
    Ok(())
}

fn set_directory(runtime: &mut Runtime, directory: &[u8]) {
    let state = runtime.win16.as_mut().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), PATH_OFFSET).unwrap();
    let mut bytes = directory.to_vec();
    bytes.push(0);
    state.selectors.write(&mut runtime.memory, pointer, &bytes).unwrap();
}

fn output(runtime: &Runtime) -> Vec<u8> {
    let state = runtime.win16.as_ref().unwrap();
    let pointer = state.selectors.pointer_from_raw(Selector(runtime.cpu.regs.ds), PATH_OFFSET).unwrap();
    let mut bytes = [0; 15];
    state.selectors.read(&runtime.memory, pointer, &mut bytes).unwrap();
    bytes[..bytes.iter().position(|byte| *byte == 0).unwrap()].to_vec()
}

#[test]
fn temporary_file_routes_write_checked_caller_buffer_and_activate_task_directories_a_b_a() {
    for route in ROUTES {
        let (mut runtime, mut host) = fixture();
        let real_address = guest_core::real_address(runtime.cpu.regs.ds, PATH_OFFSET);
        let mut original_real_bytes = [0; 15];
        runtime.memory.read(real_address, &mut original_real_bytes).unwrap();
        for (index, owner) in [OwnerId(1), OwnerId(2), OwnerId(1)].into_iter().enumerate() {
            set_directory(&mut runtime, b".\\");
            let mut expected = prepare(&mut runtime, route, owner);
            expected.set_ax(3 + index as u16);
            expected.set_carry(false);
            call(&mut runtime, &mut host, route).unwrap();
            assert_eq!(runtime.cpu.regs, expected, "{route:?}");
            let generated = format!(".\\{:08X}", 0x0c22_384e + index);
            assert_eq!(output(&runtime), generated.as_bytes());
            assert_eq!(host.calls[index], (owner, Win16CanonicalPath {
                drive: 2, components: vec![if owner == OwnerId(1) { "TASK_A" } else { "TASK_B" }.to_owned()],
            }, generated.into_bytes(), 2));
            let mut real_bytes = [0; 15];
            runtime.memory.read(real_address, &mut real_bytes).unwrap();
            assert_eq!(real_bytes, original_real_bytes, "no selector-as-real-mode writes");
        }
        assert_eq!(host.files.len(), 3);
        assert_eq!(host.handles.len(), 3);
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
        assert!(host.handles.is_empty());
        assert_eq!(host.files.len(), 3, "temporary files require explicit deletion");
    }
}

#[test]
fn temporary_file_routes_preserve_registers_and_attempted_name_on_host_failure() {
    for route in ROUTES {
        let (mut runtime, mut host) = fixture();
        let mut expected = prepare(&mut runtime, route, OwnerId(1));
        host.error = Some(DosErrorCode::AccessDenied);
        expected.set_ax(5);
        expected.set_carry(true);
        call(&mut runtime, &mut host, route).unwrap();
        assert_eq!(runtime.cpu.regs, expected, "{route:?}");
        assert_eq!(output(&runtime), b".\\0C22384E");
        assert_eq!(host.calls.len(), 1);
        assert!(host.files.is_empty());
        assert!(host.handles.is_empty());
    }
}

#[test]
fn temporary_file_routes_reject_invalid_readonly_short_freed_and_recycled_selectors() {
    for route in ROUTES {
        for selector_case in 0..6 {
            let (mut runtime, mut host) = fixture();
            prepare(&mut runtime, route, OwnerId(1));
            let state = runtime.win16.as_mut().unwrap();
            let original = state.selectors.reference(Selector(runtime.cpu.regs.ds)).unwrap();
            let base = state.selectors.describe(original).unwrap().base;
            let selector = match selector_case {
                0 => 0,
                1 => 0xfff8,
                2 => state.selectors.alloc_block(base, 0x80, AccessRights::read_only(), &runtime.memory).unwrap().raw().0,
                3 => {
                    // The 11 output bytes would fit; the documented complete
                    // prefix+13-byte capacity does not fit this selector.
                    state.selectors.alloc_block(base, u32::from(PATH_OFFSET) + 14,
                        AccessRights::read_write(), &runtime.memory).unwrap().raw().0
                }
                _ => {
                    let saved = state.selectors.alloc_block(base, 0x80, AccessRights::read_write(), &runtime.memory).unwrap();
                    state.selectors.free_block(saved).unwrap();
                    if selector_case == 5 {
                        let replacement = state.selectors.alloc_block(base, 0x80,
                            AccessRights::read_only(), &runtime.memory).unwrap();
                        assert_eq!(replacement.raw(), saved.raw());
                        assert_ne!(replacement.generation(), saved.generation());
                    }
                    saved.raw().0
                }
            };
            runtime.cpu.regs.ds = selector;
            let error = call(&mut runtime, &mut host, route).unwrap_err();
            assert_eq!(error.kind(), crate::DiagnosticKind::GuestFault, "{route:?} selector case {selector_case}");
            assert!(host.calls.is_empty());
            assert!(host.files.is_empty());
            assert!(host.handles.is_empty());
            let mut buffer = [0; 3];
            state_read_original(&runtime, original, &mut buffer);
            assert_eq!(&buffer, b".\\\0");
        }
    }
}

fn state_read_original(
    runtime: &Runtime, original: win16_abi::SelectorRef, output: &mut [u8],
) {
    let state = runtime.win16.as_ref().unwrap();
    state.selectors.read(&runtime.memory, win16_abi::SegmentedPointer::new(original, PATH_OFFSET), output).unwrap();
}

#[test]
fn temporary_file_routes_accept_exact_documented_capacity() {
    for route in ROUTES {
        let (mut runtime, mut host) = fixture();
        let mut expected = prepare(&mut runtime, route, OwnerId(1));
        let state = runtime.win16.as_mut().unwrap();
        let original = state.selectors.reference(Selector(runtime.cpu.regs.ds)).unwrap();
        let base = state.selectors.describe(original).unwrap().base;
        let exact = state.selectors.alloc_block(base, u32::from(PATH_OFFSET) + 15,
            AccessRights::read_write(), &runtime.memory).unwrap();
        runtime.cpu.regs.ds = exact.raw().0;
        expected.ds = exact.raw().0;
        expected.set_ax(3);
        expected.set_carry(false);
        call(&mut runtime, &mut host, route).unwrap();
        assert_eq!(runtime.cpu.regs, expected, "{route:?}");
        assert_eq!(output(&runtime), b".\\0C22384E");
        assert_eq!(host.calls.len(), 1);
        runtime.dos.close_all_handles_checked(&mut host).unwrap();
    }
}
